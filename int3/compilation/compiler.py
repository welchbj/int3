from __future__ import annotations

import logging
import operator
import platform
import random
from contextlib import contextmanager
from dataclasses import dataclass, field
from io import BytesIO
from itertools import pairwise
from typing import TYPE_CHECKING, Iterator, Literal, cast, overload

from llvmlite import binding as llvm
from llvmlite import ir as llvmir

from int3.architecture import Architecture, Architectures
from int3.codegen import CodeGenerator
from int3.errors import (
    Int3ArgumentError,
    Int3CompilationError,
    Int3ContextError,
    Int3ProgramDefinitionError,
)
from int3.platform import Platform, SyscallConvention, Triple

from .call_proxy import CallFactory, CallProxy
from .function_proxy import FunctionFactory, FunctionProxy, FunctionStore
from .symtab import SymbolTable
from .types import (
    BytesPointer,
    IntConstant,
    IntType,
    IntVariable,
    PyArgType,
    PyIntArgType,
    PyIntValueType,
    TypeCoercion,
    TypeManager,
)

if TYPE_CHECKING:
    from .linux_compiler import LinuxCompiler


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CodeSection:
    name: str
    address: int
    size: int
    data: bytes

    @staticmethod
    def from_section_ref(ref: llvm.SectionIteratorRef) -> CodeSection:
        maybe_name: bytes | None = ref.name()
        if maybe_name is None:
            name = ""
        else:
            name = maybe_name.decode()

        return CodeSection(
            name=name,
            address=ref.address(),
            size=ref.size(),
            data=ref.data(),
        )


@dataclass
class BytesPointerWithValue:
    bytes_ptr: BytesPointer
    value: bytes | None

    def __post_init__(self):
        if self.value is not None and len(self.value) > len(self.bytes_ptr):
            raise Int3ProgramDefinitionError(
                f"Attempted to load bytes of length {len(self.value)} into allocated space "
                f"of size {len(self.bytes_ptr)}"
            )


@dataclass
class Compiler:
    arch: Architecture
    platform: Platform
    platform_spec: str
    triple: Triple = field(init=False)

    # The name of the entrypoint function for the user-defined program.
    entry: str = "main"

    # Bytes that must be avoided when generating assembly.
    bad_bytes: bytes = b""

    # The number of bytes the entry stub will be padded to. This is required
    # to ensure the entry stub remains a static length for relocation computation.
    entry_stub_pad_len: int = 0x100

    # Interface for defining new functions on this compiler.
    def_func: FunctionFactory = field(init=False)

    # Interface for accessing created functions on this compiler.
    func: FunctionStore = field(init=False)

    # Interface for calling defined functions.
    call: CallFactory = field(init=False)

    # Short-hand for compiler types.
    types: TypeManager = field(init=False)

    # Assembly code generatgor
    codegen: CodeGenerator = field(init=False)

    # Syscall convention for this arch/platform combination.
    syscall_conv: SyscallConvention = field(init=False)

    # Wrapped llvmlite LLVM IR module.
    llvm_module: llvmir.Module = field(init=False)

    # A lookup table for allocate byte objects (keyed on their symtab index).
    _bytes_map: dict[int, BytesPointerWithValue] = field(
        init=False, default_factory=dict
    )

    # The function this compiler is currently operating on.
    _current_func: FunctionProxy | None = field(init=False, default=None)

    # The next index for a pointer in the symbol table.
    _current_symbol_index: int = field(init=False, default=0)

    def __post_init__(self):
        self.triple = Triple(self.arch, self.platform)
        self.func = FunctionStore(compiler=self)
        self.def_func = FunctionFactory(store=self.func)
        self.call = CallFactory(compiler=self)
        self.types = TypeManager(compiler=self)
        self.codegen = CodeGenerator(arch=self.arch)
        self.syscall_conv = self.triple.resolve_syscall_convention()

        # We create a fresh llvmlite context for our module. Otherwise, multiple
        # compiler instances will reference the same llvmlite library-level global
        # context.
        self.llvm_module = llvmir.Module(context=llvmir.Context())

    @property
    def current_func(self) -> FunctionProxy:
        if self._current_func is None:
            raise Int3ContextError(
                "Attempted to modify program definition without a current function set"
            )

        return self._current_func

    @property
    def builder(self) -> llvmir.IRBuilder:
        return self.current_func.llvm_builder

    @property
    def args(self) -> list[IntVariable]:
        """Interface into the current function's arguments."""
        return self.current_func.user_arg_view

    @property
    def has_entry_stub(self) -> bool:
        return self.func.func_map.get("entry_stub", None) is not None

    def reserve_symbol_index(self) -> int:
        """Reserve an index to store a pointer in the symbol table."""
        current_index = self._current_symbol_index
        self._current_symbol_index += 1
        return current_index

    def make_name(self, hint: str | None = None) -> str:
        """Make an identifier for the current function."""
        return self.current_func.make_name(hint=hint)

    @contextmanager
    def _current_function_as(self, func: FunctionProxy) -> Iterator[FunctionProxy]:
        """Context manager to set the compiler's current function."""
        if self._current_func is not None:
            raise Int3ContextError("Cannot have nested current functions")

        self._current_func = func
        try:
            yield func
        finally:
            self._current_func = None

    @overload
    def coerce_to_type(self, value: IntConstant, type: IntType) -> IntConstant: ...

    @overload
    def coerce_to_type(self, value: int, type: IntType) -> IntConstant: ...

    @overload
    def coerce_to_type(self, value: IntVariable, type: IntType) -> IntVariable: ...

    @overload
    def coerce_to_type(self, value: bytes, type: IntType) -> IntVariable: ...

    @overload
    def coerce_to_type(self, value: BytesPointer, type: IntType) -> IntVariable: ...

    def coerce_to_type(
        self, value: PyArgType, type: IntType
    ) -> IntConstant | IntVariable:
        if isinstance(value, (int, IntConstant)):
            if isinstance(value, IntConstant):
                raw_value = value.value
            else:
                raw_value = value

            return IntConstant(
                compiler=self,
                type=type,
                value=raw_value,
                wrapped_llvm_node=llvmir.Constant(
                    typ=type.wrapped_type, constant=raw_value
                ),
            )
        elif isinstance(value, (bytes, BytesPointer)):
            # Error if trying to condense to a non-native width type.
            if type.bit_size < self.arch.bit_size:
                raise Int3ProgramDefinitionError(
                    f"Cannot coerce pointer of size {self.arch.bit_size} bits to type with "
                    f"only {type.bit_size} bits"
                )

            if isinstance(value, bytes):
                value = self.b(value)

            target_llvm_type = type.wrapped_type
            new_wrapped_node = self.builder.ptrtoint(
                value.wrapped_llvm_node, target_llvm_type
            )

            return IntVariable(
                compiler=self, type=type, wrapped_llvm_node=new_wrapped_node
            )
        else:
            is_extension = value.type.bit_size < type.bit_size
            is_truncation = value.type.bit_size > type.bit_size
            should_be_signed_operation = value.type.is_signed and type.is_signed
            old_wrapped_node = value.wrapped_llvm_node
            target_llvm_type = type.wrapped_type

            if is_extension:
                if should_be_signed_operation:
                    new_wrapped_node = self.builder.sext(
                        old_wrapped_node, target_llvm_type
                    )
                else:
                    new_wrapped_node = self.builder.zext(
                        old_wrapped_node, target_llvm_type
                    )
            elif is_truncation:
                new_wrapped_node = self.builder.trunc(
                    old_wrapped_node, target_llvm_type
                )
            else:
                # We aren't changing the number of bits.
                new_wrapped_node = old_wrapped_node

            return IntVariable(
                compiler=self, type=type, wrapped_llvm_node=new_wrapped_node
            )

    def coerce(self, one: PyIntArgType, two: PyIntArgType) -> TypeCoercion:
        if isinstance(one, int) and isinstance(two, int):
            # Both arguments are raw integers.
            raise NotImplementedError("Coercion of raw integers WIP")
        elif isinstance(one, int) and not isinstance(two, int):
            # Promote one's value to two's type.
            return TypeCoercion(result_type=two.type, args=[two.make_int(one), two])
        elif not isinstance(one, int) and isinstance(two, int):
            # Promote two's value to one's type.
            return TypeCoercion(result_type=one.type, args=[one, one.make_int(two)])

        # We're dealing with two non-raw integers.
        one = cast(PyIntValueType, one)
        two = cast(PyIntValueType, two)

        if one.type == two.type:
            # They're already the same type.
            return TypeCoercion(result_type=one.type, args=[one, two])
        else:
            # Integers of different types.
            raise NotImplementedError("Coercion of typed integers WIP")

    def make_int(self, value: int, type: IntType) -> IntConstant:
        return IntConstant(
            compiler=self,
            type=type,
            wrapped_llvm_node=llvmir.Constant(typ=type.wrapped_type, constant=value),
            value=value,
        )

    def b(self, value: bytes | None = None, len_: int | None = None) -> BytesPointer:
        if value is None and len_ is None:
            raise Int3ProgramDefinitionError(
                "Must specify bytes length if no value specified"
            )
        elif value is not None and len_ is None:
            len_ = len(value)
        elif value is None and len_ is not None:
            pass
        else:
            len_ = cast(int, len_)
            value = cast(bytes, value)
            if len_ < len(value):
                raise Int3ProgramDefinitionError(
                    f"Attempted to set bytes length {len_} when literal value has length {len(value)}"
                )

        if not value:
            raise Int3ProgramDefinitionError("Cannot allocate zero-length bytes")

        new_bytes_ptr = BytesPointer(compiler=self, type=self.types.ptr, len_=len_)
        self._bytes_map[new_bytes_ptr.symtab_index] = BytesPointerWithValue(
            new_bytes_ptr, value
        )
        return new_bytes_ptr

    def i(self, value: int) -> IntConstant:
        return self.make_int(value, type=self.types.inat)

    def i8(self, value: int) -> IntConstant:
        return self.make_int(value, type=self.types.i8)

    def i16(self, value: int) -> IntConstant:
        return self.make_int(value, type=self.types.i16)

    def i32(self, value: int) -> IntConstant:
        return self.make_int(value, type=self.types.i32)

    def i64(self, value: int) -> IntConstant:
        return self.make_int(value, type=self.types.i64)

    def u(self, value: int) -> IntConstant:
        return self.make_int(value, type=self.types.unat)

    def u8(self, value: int) -> IntConstant:
        return self.make_int(value, type=self.types.u8)

    def u16(self, value: int) -> IntConstant:
        return self.make_int(value, type=self.types.u16)

    def u32(self, value: int) -> IntConstant:
        return self.make_int(value, type=self.types.u32)

    def u64(self, value: int) -> IntConstant:
        return self.make_int(value, type=self.types.u64)

    def breakpoint(self):
        llvm_func_type = llvmir.FunctionType(
            return_type=self.types.void.wrapped_type,
            args=[],
        )

        self.builder.comment("breakpoint")
        self.builder.asm(
            ftype=llvm_func_type,
            asm=self.codegen.breakpoint(),
            constraint="",
            args=[],
            side_effect=True,
        )

    def add(self, one: PyIntArgType, two: PyIntArgType) -> IntVariable:
        coercion = self.coerce(one, two)
        result_inst = self.builder.add(
            coercion.args[0].wrapped_llvm_node,
            coercion.args[1].wrapped_llvm_node,
            name=self.make_name(hint="res"),
        )
        return IntVariable(
            compiler=self,
            type=coercion.result_type,
            wrapped_llvm_node=result_inst,
        )

    def ret(self, value: PyIntArgType | None = None):
        if value is None and self.current_func.return_type == self.types.void:
            return self.builder.ret_void()
        elif value is None:
            raise Int3CompilationError(
                "No return value specified for non-void function"
            )
        elif self.current_func.return_type == self.types.void:
            raise Int3CompilationError(
                f"Attempting to return value from void function: {value}"
            )
        else:
            return_type = cast(IntType, self.current_func.return_type)
            value = self.coerce_to_type(value, type=return_type)
            return self.builder.ret(value.wrapped_llvm_node)

    def llvm_ir(self) -> str:
        llvm_mod_str = str(self.llvm_module)

        # We hot patch the preliminary LLVM IR to include a prefix before each function. This
        # allows us to map functions to their compiled bytes in LLVM's output format.
        #
        # XXX: Should consider submitting a patch to llvmlite to allow for API-level
        #      prefix definitions, which would make this hack unnecessary.
        for func in self.func.func_map.values():
            llvm_mod_str = self._patch_in_func_prefix(llvm_mod_str, func)

        return llvm_mod_str

    def _patch_in_func_prefix(self, llvm_ir_str: str, func: FunctionProxy) -> str:
        """LLVM IR source-level patching to add function prefixes."""
        func_def_start = f'@"{func.name}"('

        func_def_start_idx = llvm_ir_str.find(func_def_start)
        if func_def_start_idx == -1:
            raise Int3CompilationError(
                f"Unable to find function start needle in LLVM IR: {func_def_start}"
            )

        func_def_end_idx = llvm_ir_str.find(")", func_def_start_idx)
        if func_def_end_idx == -1:
            raise Int3CompilationError("Unable to find function end needle in LLVM IR")

        prefix_ir = f' prefix [{len(func.prefix_marker)} x i8] c"{func.prefix_marker}"'
        llvm_ir_str = (
            llvm_ir_str[: func_def_end_idx + 1]
            + prefix_ir
            + llvm_ir_str[func_def_end_idx + 1 :]
        )
        return llvm_ir_str

    def _get_text_from_object(self, raw_object: bytes) -> bytes:
        """Extract the text section from an object file."""
        obj_file_ref = llvm.ObjectFileRef.from_data(raw_object)

        sections: list[CodeSection] = []
        for section_ref in obj_file_ref.sections():
            if not section_ref.is_text():
                logger.debug(f"Skipping non-text section {section_ref.name()}")
                continue

            sections.append(CodeSection.from_section_ref(section_ref))

        if len(sections) != 1:
            raise Int3CompilationError(
                f"Expected 1 code section after compilation but got {len(sections)}"
            )

        return sections[0].data

    def _llvm_module_to_text(self) -> bytes:
        target = llvm.Target.from_triple(str(self.triple))

        # codemodel influences the range of relative branches/calls.
        #
        # See: https://stackoverflow.com/a/40498306
        target_machine = target.create_target_machine(
            opt=0, reloc="pic", codemodel="small"
        )
        target_machine.set_asm_verbosity(verbose=True)

        llvm_ir_str = self.llvm_ir()
        logger.debug(f"Generated LLVM IR program:\n{llvm_ir_str}")

        llvm_mod = llvm.parse_assembly(llvm_ir_str)
        llvm_mod.verify()

        raw_object = cast(bytes, target_machine.emit_object(llvm_mod))
        return self._get_text_from_object(raw_object)

    def compile_funcs(self) -> dict[str, bytes]:
        # Compile the raw object.
        text_bytes = self._llvm_module_to_text()

        # Deduce each function's bytes by identifying all locations of prefix strings.
        prefix_indexes: list[tuple[int, FunctionProxy]] = []
        for func in self.func.func_map.values():
            idx = text_bytes.find(func.prefix_marker.encode())
            if idx == -1:
                raise Int3CompilationError(
                    f"Unable to find expected prefix string in compiled code: {func.prefix_marker}"
                )
            prefix_indexes.append((idx + len(func.prefix_marker), func))

        # Iterate over the functions sorted by positions and leverage
        # their intervals to infer compiled code.
        sorted_funcs = list(sorted(prefix_indexes, key=operator.itemgetter(0)))
        func_bytes: dict[str, bytes] = {}
        for this_func_tuple, next_func_tuple in pairwise(sorted_funcs):
            this_func_pos, this_func = this_func_tuple
            next_func_pos, next_func = next_func_tuple

            func_bytes[this_func.name] = text_bytes[
                this_func_pos : next_func_pos - len(next_func.prefix_marker)
            ]

        last_func_pos, last_func = sorted_funcs[-1]
        func_bytes[last_func.name] = text_bytes[last_func_pos:]

        return func_bytes

    def compile(self) -> bytes:
        # Compile all of our functions into raw bytes.
        compiled_funcs = self.compile_funcs()

        # Combine our compiled functions, making note of the offset of each
        # function for use in constructing the symtab.
        func_offsets: dict[str, int] = {}
        program = b""
        for func_name, func_bytes in compiled_funcs.items():
            pos = len(program)
            func_offsets[func_name] = pos
            logger.debug(
                f"Wrote function {func_name} of length {len(func_bytes)} to position {pos}"
            )
            program += func_bytes

        logger.debug(f"Function offsets: {func_offsets}")

        # Using the offset of each function, we construct our entry stub that
        # setups up our symtab construct.
        entry_stub = self._make_entry_stub(func_offsets)

        # Pad the entry stub to a static length so it can use predictable offsets.
        if len(entry_stub) > self.entry_stub_pad_len:
            raise Int3CompilationError(
                f"Compilation of symtab used {len(entry_stub)} bytes when only "
                f"{self.entry_stub_pad_len} reserved"
            )
        pad_len = self.entry_stub_pad_len - len(entry_stub)
        preamble = entry_stub + self.codegen.nop_pad(pad_len)

        # Add the remaining function definitions. Its important that they're added here
        # in the same order that they were passed to the entry stub generation.
        return preamble + program

    def _make_entry_stub(self, func_offsets: dict[str, int]) -> bytes:
        pc_transfer_reg = random.choice(self.arch.gp_regs)
        get_pc_stub = self.codegen.compute_pc(result=pc_transfer_reg).bytes

        sub_cc = self.clean_slate()
        with sub_cc.def_func.entry_stub():
            # Inline assembly to get the result of the compute PC assembly above.
            llvm_func_type = llvmir.FunctionType(
                return_type=self.types.unat.wrapped_type, args=[]
            )
            stored_pc_inst = sub_cc.builder.asm(
                ftype=llvm_func_type,
                # XXX: This may need to be changed for different architectures.
                asm=f"mov %{pc_transfer_reg}, $0",
                constraint="=r",
                args=[],
                side_effect=False,
            )
            stored_pc = IntVariable(
                compiler=self, type=self.types.unat, wrapped_llvm_node=stored_pc_inst
            )

            # It's important that we don't initialize the SymbolTable instance until
            # now, as it derives its number of required slots from the compiler's
            # current state.
            symtab = SymbolTable(
                funcs=self.func, num_slots=self._current_symbol_index, compiler=sub_cc
            )
            symtab_ptr = symtab.alloc()

            # Initialize bytes objects in the symbol table.
            for symtab_idx, bytes_ptr_with_value in self._bytes_map.items():
                bytes_ptr = bytes_ptr_with_value.bytes_ptr
                initial_bytes = bytes_ptr_with_value.value

                sub_cc.builder.comment(
                    f"Setup symtab for byte pointer (index {symtab_idx})"
                )

                # Allocate stack space for the bytes pointer in the entry stub's stack frame.
                byte_type = sub_cc.types.i8.wrapped_type
                bytes_allocated_stack_ptr = sub_cc.builder.alloca(
                    typ=byte_type, size=bytes_ptr.aligned_len
                )

                # Fill the allocated stack space with the user-specified initial value (if one
                # exists).
                if initial_bytes is not None:
                    reg_size = sub_cc.arch.byte_size
                    initial_bytes = initial_bytes.ljust(bytes_ptr.aligned_len, b"\x00")
                    with BytesIO(initial_bytes) as f:
                        idx = 0
                        while True:
                            chunk = f.read(reg_size)
                            if not chunk:
                                break

                            chunk_llvm_node = sub_cc.u(
                                sub_cc.arch.unpack(chunk)
                            ).wrapped_llvm_node

                            chunk_ptr = sub_cc.builder.gep(
                                ptr=bytes_allocated_stack_ptr,
                                indices=[sub_cc.i32(idx).wrapped_llvm_node],
                                inbounds=True,
                                source_etype=sub_cc.types.unat.wrapped_type,
                            )
                            chunk_ptr.type.is_opaque = True
                            sub_cc.builder.store(chunk_llvm_node, chunk_ptr, align=True)

                            idx += 1

                # Write the stack address into the symbol table.
                symtab_slot_ptr = symtab.slot_ptr(
                    symtab_ptr, idx=bytes_ptr.symtab_index
                )
                # XXX: Is it an llvmlite bug that alloca returns a typed pointer?
                symtab_slot_ptr.type.is_opaque = True
                sub_cc.builder.store(bytes_allocated_stack_ptr, symtab_slot_ptr)

            # Initialize function pointers in the symbol table.
            for func_name, func in self.func.func_map.items():
                sub_cc.builder.comment(
                    f"Setup symtab for function {func_name} (index {func.symtab_index})"
                )
                symtab_slot_ptr = symtab.slot_ptr(symtab_ptr, idx=func.symtab_index)
                symtab_slot_ptr.type.is_opaque = True

                relative_func_offset = (
                    self.entry_stub_pad_len - len(get_pc_stub) + func_offsets[func_name]
                )
                relocated_addr = sub_cc.add(stored_pc, relative_func_offset)
                sub_cc.builder.store(relocated_addr.wrapped_llvm_node, symtab_slot_ptr)

            # Call the user entrypoint function.
            entry_func = self.func.func_map.get(self.entry, None)
            if entry_func is None:
                raise Int3CompilationError(
                    f"No definition for entrypoint: {self.entry}"
                )

            # Entry the conventions of the entrypoint function match our desired characteristics.
            #
            # We allow one argument for the entrypoint function to account for the implicit symtab
            # pointer that will be passed to it.
            if len(entry_func.arg_types) != 1:
                raise Int3CompilationError(
                    f"Expected no arguments for entrypoint but got: {entry_func.arg_types}"
                )
            elif entry_func.return_type != self.types.void:
                raise Int3CompilationError(
                    f"Expected void return type for entrypoint but got: {entry_func.return_type}"
                )

            CallProxy.call_func(
                func=entry_func,
                compiler=sub_cc,
                symtab_ptr=symtab_ptr,
                args=tuple(),
            )

        stub_program = get_pc_stub
        stub_program += sub_cc.compile_funcs()["entry_stub"]
        return stub_program

    def clean_slate(self) -> Compiler:
        """Create a fresh compiler targeting the same platform."""
        return self.from_str(platform_spec=self.platform_spec, bad_bytes=self.bad_bytes)

    @staticmethod
    def from_host(bad_bytes: bytes = b"") -> Compiler:
        os_type = platform.system().lower()
        arch = Architectures.from_host().name
        return Compiler.from_str(f"{os_type}/{arch}", bad_bytes=bad_bytes)

    @overload
    @staticmethod
    def from_str(
        platform_spec: Literal["linux/x86_64"], bad_bytes: bytes = b""
    ) -> "LinuxCompiler": ...

    @overload
    @staticmethod
    def from_str(platform_spec: str, bad_bytes: bytes = b"") -> Compiler: ...

    @staticmethod
    def from_str(platform_spec: str, bad_bytes: bytes = b"") -> Compiler:
        parts = platform_spec.split("/")
        if len(parts) != 2:
            raise Int3ArgumentError(f"Invalid platform spec: {platform_spec}")

        platform = Platform.from_str(parts[0])
        match platform:
            case Platform.Linux:
                from .linux_compiler import LinuxCompiler

                compiler_cls = LinuxCompiler
            case Platform.Windows:
                raise NotImplementedError(f"Windows support not yet implemented")

        arch = Architectures.from_str(parts[1])
        return compiler_cls(
            arch=arch,
            platform=platform,
            platform_spec=platform_spec,
            bad_bytes=bad_bytes,
        )
