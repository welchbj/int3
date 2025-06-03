from __future__ import annotations

import logging
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
        return CodeSection(
            name=ref.name(),
            address=ref.address(),
            size=ref.size(),
            data=ref.data(),
        )


@dataclass
class Compiler:
    arch: Architecture
    platform: Platform
    triple: Triple = field(init=False)

    # The name of the entrypoint function for the compiler.
    entry: str = "main"

    # Bytes that must be avoided when generating assembly.
    bad_bytes: bytes = b""

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
        self.codegen = CodeGenerator(compiler=self)
        self.syscall_conv = self.triple.resolve_syscall_convention()
        self.llvm_module = llvmir.Module()

    def __bytes__(self) -> bytes:
        return self.to_bytes()

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
        return str(self.llvm_module)

    def to_bytes(self) -> bytes:
        raw_obj_data = self._compile(mode="bytes")

        obj_file_ref = llvm.ObjectFileRef.from_data(raw_obj_data)

        code_sections: list[CodeSection] = []
        for section_ref in obj_file_ref.sections():
            if not section_ref.is_text():
                logger.debug(f"Skipping non-text section {section_ref.name()}")
                continue

            code_sections.append(CodeSection.from_section_ref(section_ref))

        data = b""
        for code_section in code_sections:
            # XXX: We need to validate that all of the sections are contiguous.
            data += code_section.data

        return data

    def to_asm(self) -> str:
        return self._compile(mode="asm")

    @overload
    def _compile(self, mode: Literal["asm"]) -> str: ...

    @overload
    def _compile(self, mode: Literal["bytes"]) -> bytes: ...

    def _compile(self, mode: Literal["asm", "bytes"]) -> str | bytes:
        target = llvm.Target.from_triple(str(self.triple))

        # codemodel influences the range of relative branches/calls.
        #
        # See: https://stackoverflow.com/a/40498306
        target_machine = target.create_target_machine(
            opt=0, reloc="pic", codemodel="large"
        )
        target_machine.set_asm_verbosity(verbose=True)

        llvm_mod = llvm.parse_assembly(str(self.llvm_module))
        llvm_mod.verify()

        with llvm.create_mcjit_compiler(llvm_mod, target_machine) as engine:
            engine.finalize_object()
            if mode == "asm":
                return cast(str, target_machine.emit_assembly(llvm_mod))
            else:
                return cast(bytes, target_machine.emit_object(llvm_mod))

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
