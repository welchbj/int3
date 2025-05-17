from __future__ import annotations

import random
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Iterator, Literal, overload

from int3.architecture import Architecture, Architectures
from int3.codegen import CodeGenerator
from int3.errors import Int3ArgumentError, Int3InsufficientWidthError
from int3.ir import (
    AnyBytesType,
    AnyIntType,
    IrBranch,
    IrConstant,
    IrIntConstant,
    IrIntType,
    IrIntVariable,
    IrOperation,
    IrOperator,
    IrVariable,
)

if TYPE_CHECKING:
    from ._linux_compiler import LinuxCompiler

from .block import Block
from .scope import Scope

_ENTRY_LABEL_NAME = "entry"


@dataclass
class Compiler:
    arch: Architecture

    # The entrypoint of the program.
    entry: Block = field(init=False)

    # The stack used to maintain the concept of the compiler's "current" block.
    block_stack: list[Block] = field(init=False)

    # All blocks ever created by this compiler.
    blocks: list[Block] = field(init=False, default_factory=list)

    code_generator: CodeGenerator = field(init=False)

    # Mapping of IR labels to their associated blocks.
    label_map: dict[str, Block] = field(init=False)

    def __post_init__(self):
        self.entry = Block(
            compiler=self, scope_stack=[Scope()], label=_ENTRY_LABEL_NAME
        )
        self.blocks = [self.entry]
        self.block_stack = [self.entry]
        self.label_map = {_ENTRY_LABEL_NAME: self.entry}

    @property
    def current_block(self) -> Block:
        """The IR block the compiler is currently operating on.

        Most user-facing compiler operations will implicitly modify the block
        this property references.

        """
        return self.block_stack[-1]

    def _spawn_block(
        self,
        new_scope: bool = True,
        inherit_scope: bool = True,
        base_block: Block | None = None,
        name_hint: str | None = None,
    ) -> Block:
        if name_hint is None:
            name_hint = "block"

        if base_block is None:
            base_block = self.current_block

        if inherit_scope:
            scope_stack = list(base_block.scope_stack)
        else:
            scope_stack = []

        if new_scope:
            scope_stack.append(Scope())

        new_label = self._make_unique_label(name_hint)
        new_block = Block(compiler=self, scope_stack=scope_stack, label=new_label)

        self.label_map[new_label] = new_block
        self.blocks.append(new_block)

        return new_block

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

            return maybe_label

    def _make_int_var(
        self, signed: bool, bit_size: int, value: int | None = None
    ) -> IrIntVariable:
        if bit_size > self.arch.bit_size:
            raise Int3InsufficientWidthError(
                f"Cannot represent values of width {bit_size} on arch {self.arch.name}"
            )

        new_var = IrIntVariable(signed=signed, bit_size=bit_size)
        self.current_block.lowest_scope.add_var(new_var)
        if value is not None:
            self.mov(
                new_var, IrIntConstant(signed=signed, bit_size=bit_size, value=value)
            )

        return new_var

    def i(self, value: int | None = None) -> IrIntVariable:
        """Create a signed int var for the architecture's native bit width."""
        return self._make_int_var(signed=True, bit_size=self.arch.bit_size, value=value)

    def u(self, value: int | None = None) -> IrIntVariable:
        """Create an unsigned int var for the architecture's native bit width."""
        return self._make_int_var(
            signed=False, bit_size=self.arch.bit_size, value=value
        )

    def ir_str(self) -> str:
        return "\n".join(str(block) for block in self.blocks)

    @contextmanager
    def current_block_as(self, block: Block) -> Iterator[Block]:
        """Context manager to set the compiler's current block."""
        self.block_stack.append(block)

        try:
            yield block
        finally:
            self.block_stack.pop()

    @contextmanager
    def if_else(self, branch: IrBranch) -> Iterator[tuple[Block, Block]]:
        if_else_block = self._spawn_block(name_hint="branch")
        inner_if_block = self._spawn_block(
            base_block=if_else_block, name_hint=f"{if_else_block.label}_if"
        )
        inner_else_block = self._spawn_block(
            base_block=if_else_block, name_hint=f"{if_else_block.label}_else"
        )

        with self.current_block_as(if_else_block):
            self._branch_if_else(branch, inner_if_block, inner_else_block)
            yield inner_if_block, inner_else_block

    def mov(self, dest: IrVariable, src: AnyBytesType | AnyIntType):
        if isinstance(src, int):
            if src < 0:
                src = self.i(src)
            else:
                src = self.u(src)
        elif isinstance(src, bytes):
            raise NotImplementedError("bytes operand support not yet implemented")

        self.add_operation(
            IrOperation(operator=IrOperator.Mov, result=dest, args=[src])
        )

        dest.is_unbound = False

    def add(self, dest: IrVariable, one: IrVariable, two: IrVariable | IrConstant): ...

    def xor(self, dest: IrVariable, one: IrVariable, two: IrVariable | IrConstant): ...

    def sub(self, dest: IrVariable, one: IrVariable, two: IrVariable | IrConstant): ...

    def call(self, target: Block): ...

    def _branch_if_else(self, branch: IrBranch, if_target: Block, else_target: Block):
        branch.set_targets(if_target.label, else_target.label)
        self.add_operation(branch)

    def add_operation(self, operation: IrBranch | IrOperation):
        """Interface for adding a raw TODO."""
        self.current_block.add_operation(operation)

    @overload
    @staticmethod
    def from_str(platform_spec: Literal["linux/x86_64"]) -> "LinuxCompiler": ...

    @overload
    @staticmethod
    def from_str(platform_spec: str) -> Compiler: ...

    @staticmethod
    def from_str(platform_spec: str) -> Compiler:
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
        return compiler_cls(arch)
