from __future__ import annotations

import logging
import platform
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Iterator, Literal, overload

from llvmlite import binding as llvm
from llvmlite import ir as llvmir

from int3.architecture import Architecture, Architectures
from int3.errors import Int3ArgumentError, Int3ContextError

if TYPE_CHECKING:
    from ._linux_compiler import LinuxCompiler

from .function_proxy import FunctionFactory, FunctionProxy

logger = logging.getLogger(__name__)


type IrArgType = llvmir.Constant


@dataclass
class IrTypes:
    # XXX: Likely need our own wrappers around int types.

    # See: https://stackoverflow.com/a/14723945

    arch: Architecture

    inat: llvmir.IntType = field(init=False)
    i8: llvmir.IntType = field(init=False)
    i16: llvmir.IntType = field(init=False)
    i32: llvmir.IntType = field(init=False)
    i64: llvmir.IntType = field(init=False)

    void: llvmir.VoidType = field(init=False)

    def __post_init__(self):
        self.inat = llvmir.IntType(bits=self.arch.bit_size)
        self.i8 = llvmir.IntType(bits=8)
        self.i16 = llvmir.IntType(bits=16)
        self.i32 = llvmir.IntType(bits=32)
        self.i64 = llvmir.IntType(bits=64)

        self.void = llvmir.VoidType()


@dataclass
class Compiler:
    arch: Architecture

    # The name of the entrypoint function for the compiler.
    entry: str = "main"

    # Bytes that must be avoided when generating assembly.
    bad_bytes: bytes = b""

    # Interface for creating functions on this compiler.
    func: FunctionFactory = field(init=False)

    # The function this compiler is currently operating on.
    _current_func: FunctionProxy | None = field(init=False, default=None)

    # Short-hand for llvmlite types.
    types: IrTypes = field(init=False)

    # Wrapped llvmlite IR module.
    llvm_module: llvmir.Module = field(init=False)

    def __post_init__(self):
        llvm.initialize()
        llvm.initialize_native_target()
        llvm.initialize_native_asmprinter()

        self.func = FunctionFactory(compiler=self)
        self.types = IrTypes(arch=self.arch)
        self.llvm_module = llvmir.Module()

    @property
    def current_func(self) -> FunctionProxy:
        if self._current_func is None:
            raise Int3ContextError(
                "Attempted to modify program definition without a current function set"
            )

        return self._current_func

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

    def i(self, value: int) -> llvmir.Constant:
        return self.types.inat(value)

    def i32(self, value: int) -> llvmir.Constant:
        return self.types.i32(value)

    def add(self, one: IrArgType, two: IrArgType) -> ...:
        name = self.current_func.make_name(hint="result")
        return self.current_func.llvm_builder.add(one, two, name=name)

    def ret(self, value: IrArgType):
        return self.current_func.llvm_builder.ret(value)

    def llvm_ir(self) -> str:
        return str(self.llvm_module)

    def compile_to_asm(self) -> str:
        return self._compile(mode="asm")

    def _compile(self, mode: Literal["asm", "bytes"]) -> str | bytes:
        # XXX: We may need to inject the target LLVM triple here.
        #
        # See: https://stackoverflow.com/a/40890321
        target = llvm.Target.from_triple("x86_64-pc-linux-gnu")
        # XXX: opt is disabled for dev purposes.
        target_machine = target.create_target_machine(opt=0)

        llvm_mod = llvm.parse_assembly(str(self.llvm_module))
        llvm_mod.verify()

        with llvm.create_mcjit_compiler(llvm_mod, target_machine) as engine:
            engine.finalize_object()
            if mode == "asm":
                return target_machine.emit_assembly(llvm_mod)
            else:
                return target_machine.emit_object(llvm_mod)

    # @contextmanager
    # def if_else(self, pred) -> Iterator[tuple[Block, Block]]:
    #     if_else_block = self.current_func._spawn_block(name_hint="branch")
    #     # TODO: Do blocks need to annotate who their successor should be?
    #     #       We may need this context to properly order blocks at the LLIR or codegen level.
    #     after_if_else_block = self.current_func._spawn_block(name_hint="after_if_else")
    #     inner_if_block = self.current_func._spawn_block(
    #         base_block=if_else_block, name_hint=f"{if_else_block.label}_if"
    #     )
    #     inner_else_block = self.current_func._spawn_block(
    #         base_block=if_else_block, name_hint=f"{if_else_block.label}_else"
    #     )

    #     with self.current_func._current_block_as(if_else_block):
    #         self._branch_if_else(branch, inner_if_block, inner_else_block)
    #         yield inner_if_block, inner_else_block

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

        os_name = parts[0]
        match os_name.lower():
            case "linux":
                from ._linux_compiler import LinuxCompiler

                compiler_cls = LinuxCompiler
            case "windows":
                raise NotImplementedError(f"Windows support not yet implemented")
            case _:
                raise Int3ArgumentError(f"Unknown platform string {os_name}")

        arch = Architectures.from_str(parts[1])
        return compiler_cls(arch=arch, bad_bytes=bad_bytes)
