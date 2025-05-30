from __future__ import annotations

import logging
import random
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Iterator, Literal, overload

from int3.architecture import Architecture, Architectures
from int3.codegen import CodeGenerator
from int3.errors import Int3ArgumentError, Int3ContextError, Int3InsufficientWidthError
from int3.ir import (
    HlirAnyBytesType,
    HlirAnyIntType,
    HlirBranch,
    HlirIntConstant,
    HlirIntVariable,
    HlirOperation,
    HlirOperator,
    HlirVariable,
)

if TYPE_CHECKING:
    from ._linux_compiler import LinuxCompiler

from .block import Block
from .flattener import FlattenedProgram, Flattener
from .function import Function, FunctionFactory

logger = logging.getLogger(__name__)


@dataclass
class Compiler:
    arch: Architecture

    # The name of the entrypoint function for the compiler.
    entry: str = "main"

    # Bytes that must be avoided when generating assembly.
    bad_bytes: bytes = b""

    # Interface for creating functions on this compiler.
    func: FunctionFactory = field(init=False)

    # Mapping of IR labels to their associated blocks.
    label_map: dict[str, Block] = field(init=False, default_factory=dict)

    # The function this compiler is currently operating on.
    _current_func: Function | None = field(init=False, default=None)

    def __post_init__(self):
        self.func = FunctionFactory(compiler=self)

    @property
    def current_func(self) -> Function:
        if self._current_func is None:
            raise Int3ContextError(
                "Attempted to modify program definition without a current function set"
            )

        return self._current_func

    def _make_unique_label(self, hint: str) -> str:
        """Generate a label with a unique name.

        This method should not be used directly. Rather, _spawn_block
        uses this method to associate a new label with a new block.

        """
        while True:
            rand_str = "".join(random.choice("0123456789abcdef") for _ in range(4))
            maybe_label = f"{hint}_{rand_str}"

            if maybe_label in self.label_map.keys():
                continue

            logging.debug(f"Created label {maybe_label}")
            return maybe_label

    def _make_int_var(
        self, signed: bool, bit_size: int, value: int | None = None
    ) -> HlirIntVariable | HlirIntConstant:
        if bit_size > self.arch.bit_size:
            raise Int3InsufficientWidthError(
                f"Cannot represent values of width {bit_size} on arch {self.arch.name}"
            )

        if value is not None:
            return HlirIntConstant(
                compiler=self, signed=signed, bit_size=bit_size, value=value
            )
        else:
            scope = self.current_func.current_block.lowest_scope
            new_var_name = scope.allocate_var_name(prefix="var")
            new_var = HlirIntVariable(
                compiler=self, name=new_var_name, signed=signed, bit_size=bit_size
            )
            scope.add_var(new_var)
            return new_var

    @contextmanager
    def _current_function_as(self, func: Function) -> Iterator[Function]:
        """Context manager to set the compiler's current function."""
        if self._current_func is not None:
            raise Int3ContextError("Cannot have nested current functions")

        self._current_func = func
        try:
            yield func
        finally:
            self._current_func = None

    @overload
    def i(self, value: int) -> HlirIntConstant: ...

    @overload
    def i(self, value: None = None) -> HlirIntVariable: ...

    def i(self, value: int | None = None) -> HlirIntVariable | HlirIntConstant:
        """Create a signed int variable or constant for the architecture's native bit width."""
        return self._make_int_var(signed=True, bit_size=self.arch.bit_size, value=value)

    @overload
    def u(self, value: int) -> HlirIntConstant: ...

    @overload
    def u(self, value: None = None) -> HlirIntVariable: ...

    def u(self, value: int | None = None) -> HlirIntVariable | HlirIntConstant:
        """Create an unsigned int variable or constant for the architecture's native bit width."""
        return self._make_int_var(
            signed=False, bit_size=self.arch.bit_size, value=value
        )

    def ir_str(self) -> str:
        return "\n".join(str(func) for func in self.func.func_map.values())

    def flatten(self) -> FlattenedProgram:
        return Flattener(self).flatten()

    @contextmanager
    def if_else(self, branch: HlirBranch) -> Iterator[tuple[Block, Block]]:
        if_else_block = self.current_func._spawn_block(name_hint="branch")
        inner_if_block = self.current_func._spawn_block(
            base_block=if_else_block, name_hint=f"{if_else_block.label}_if"
        )
        inner_else_block = self.current_func._spawn_block(
            base_block=if_else_block, name_hint=f"{if_else_block.label}_else"
        )

        with self.current_func._current_block_as(if_else_block):
            self._branch_if_else(branch, inner_if_block, inner_else_block)
            yield inner_if_block, inner_else_block

    def mov(self, dest: HlirVariable, src: HlirAnyBytesType | HlirAnyIntType):
        if isinstance(src, int):
            if src < 0:
                src = self.i(src)
            else:
                src = self.u(src)
        elif isinstance(src, bytes):
            raise NotImplementedError("bytes operand support not yet implemented")

        self.add_operation(
            HlirOperation(operator=HlirOperator.Mov, result=dest, args=[src])
        )

        dest.is_unbound = False

    def add_operation(self, operation: HlirBranch | HlirOperation):
        """Interface for adding a raw operation to the current block."""
        self.current_func.current_block.add_operation(operation)

    def _branch_if_else(self, branch: HlirBranch, if_target: Block, else_target: Block):
        branch.set_targets(if_target.label, else_target.label)
        self.add_operation(branch)

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
