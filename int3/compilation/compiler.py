from __future__ import annotations

import logging
import operator
import platform
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Iterator, Literal, cast, overload

from llvmlite import binding as llvm
from llvmlite import ir as llvmir

from int3.architecture import Architecture, Architectures
from int3.codegen import CodeGenerator
from int3.errors import Int3ArgumentError, Int3CompilationError, Int3ContextError
from int3.platform import Platform, SyscallConvention, Triple

from .symtab import SymbolTable

if TYPE_CHECKING:
    from ._linux_compiler import LinuxCompiler

from .function_proxy import FunctionFactory, FunctionProxy
from .types import (
    ArgType,
    IntArgType,
    IntConstant,
    IntType,
    IntValueType,
    IntVariable,
    TypeCoercion,
    TypeManager,
)

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
class Compiler:
    arch: Architecture
    platform: Platform
    triple: Triple = field(init=False)

    # The name of the entrypoint function for the user-defined program.
    entry: str = "main"

    # Bytes that must be avoided when generating assembly.
    bad_bytes: bytes = b""

    # The number of bytes the entry stub will be padded to. This is required
    # to ensure the entry stub remains a static length for relocation computation.
    entry_stub_pad_len: int = 100

    # Interface for creating functions on this compiler.
    func: FunctionFactory = field(init=False)

    # Short-hand for compiler types.
    types: TypeManager = field(init=False)

    # Assembly code generatgor
    codegen: CodeGenerator = field(init=False)

    # Syscall convention for this arch/platform combination.
    syscall_conv: SyscallConvention = field(init=False)

    # Wrapped llvmlite LLVM IR module.
    llvm_module: llvmir.Module = field(init=False)

    # The function this compiler is currently operating on.
    _current_func: FunctionProxy | None = field(init=False, default=None)

    def __post_init__(self):
        self.triple = Triple(self.arch, self.platform)
        self.func = FunctionFactory(compiler=self)
        self.types = TypeManager(compiler=self)
        self.codegen = CodeGenerator(arch=self.arch)
        self.syscall_conv = self.triple.resolve_syscall_convention()
        self.llvm_module = llvmir.Module()

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
        return self.current_func.args

    @property
    def has_entry_stub(self) -> bool:
        return self.func.func_map.get("entry_stub", None) is not None

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

    def coerce_to_type(
        self, value: IntArgType, type: IntType
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

    def coerce(self, one: IntArgType, two: IntArgType) -> TypeCoercion:
        if isinstance(one, int) and isinstance(two, int):
            # Both arguments are raw integers.
            raise NotImplementedError("Coercion of raw integers WIP")
        elif isinstance(one, int) and not isinstance(two, int):
            # Promote one's value to two's type.
            return TypeCoercion(result_type=two.type, args=[two.make_int(one), two])
        elif not isinstance(one, int) and isinstance(two, int):
            # Promote two's value to the one's type.
            return TypeCoercion(result_type=one.type, args=[one, one.make_int(two)])

        # We're dealing with two non-raw integers.
        one = cast(IntValueType, one)
        two = cast(IntValueType, two)

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

    def add(self, one: IntArgType, two: IntArgType) -> IntVariable:
        coercion = self.coerce(one, two)
        result_inst = self.builder.add(
            coercion.args[0].wrapped_llvm_node,
            coercion.args[1].wrapped_llvm_node,
            name=self.make_name(hint="result"),
        )
        return IntVariable(
            compiler=self,
            type=coercion.result_type,
            wrapped_llvm_node=result_inst,
        )

    def ret(self, value: ArgType | None = None):
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
        if not self.has_entry_stub:
            self._init_entry_stub()

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
        # TODO
        ...

    def compile(self) -> bytes:
        # TODO: We probably need to compile the entry_stub only after we've compiled the
        #       rest of the functions.

        target = llvm.Target.from_triple(str(self.triple))

        # codemodel influences the range of relative branches/calls.
        #
        # See: https://stackoverflow.com/a/40498306
        target_machine = target.create_target_machine(
            opt=0, reloc="pic", codemodel="small"
        )
        target_machine.set_asm_verbosity(verbose=True)

        llvm_mod = llvm.parse_assembly(self.llvm_ir())
        llvm_mod.verify()

        raw_object = cast(bytes, target_machine.emit_object(llvm_mod))
        text_bytes = self._get_text_from_object(raw_object)

        print(f"{text_bytes = }")

        # Deduce each function's bytes by identifying all locations of prefix strings.
        func_bytes: dict[str, bytes] = {}
        prefix_indexes = []
        for func in self.func.func_map.values():
            idx = text_bytes.find(func.prefix_marker.encode())
            if idx == -1:
                raise Int3CompilationError(
                    f"Unable to find expected prefix string in compiled code: {func.prefix_marker}"
                )

            # TODO: How do we resolve the function back from this?
            prefix_indexes.append((idx + len(func.prefix_marker), func))

        for prefix_index in sorted(prefix_indexes, key=operator.itemgetter(0)):
            print(prefix_index[0])

        1 / 0
        # TODO

        # Pad the entry stub to a static length so it can use predictable offsets.
        program = func_bytes.pop("entry_sub")
        self.codegen.nop_pad(
            func_bytes["entry_stub"], pad_len=self.entry_stub_pad_len
        )

        # Add the remaining TODO.

        # TODO

    def _init_entry_stub(self, func_offsets: dict[str, int]):
        # XXX: We may want to refresh the entry stub if new functions have been defined.

        with self.func.entry_stub():
            # TODO: Inline assembly to get current PC

            symtab = SymbolTable(compiler=self)
            symtab_ptr = symtab.alloc()

            for func_name in symtab.entry_slot_map.keys():
                func_obj = self.func.func_map[func_name]

                self.builder.comment(f"Setup symtab for function {func_name}")
                func_ptr = symtab.func_slot_ptr(symtab_ptr, func_name)
                # TODO: Compute function offset and store in slot; below is incorrect
                self.builder.store(func_obj.llvm_func, func_ptr)

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
                from ._linux_compiler import LinuxCompiler

                compiler_cls = LinuxCompiler
            case Platform.Windows:
                raise NotImplementedError(f"Windows support not yet implemented")

        arch = Architectures.from_str(parts[1])
        return compiler_cls(arch=arch, platform=platform, bad_bytes=bad_bytes)
