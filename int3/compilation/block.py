from __future__ import annotations

from dataclasses import dataclass, field
from types import TracebackType
from typing import TYPE_CHECKING, ContextManager

from int3._interfaces import PrintableIr
from int3.errors import Int3MissingEntityError
from int3.ir import (
    HlirBranch,
    HlirBytesVariable,
    HlirIntVariable,
    HlirLabel,
    HlirOperation,
    HlirVariable,
)

if TYPE_CHECKING:
    from .compiler import Compiler
    from .scope import Scope


@dataclass
class Block(PrintableIr):
    compiler: "Compiler"
    scope_stack: list["Scope"]
    operations: list[HlirBranch | HlirOperation] = field(
        init=False, default_factory=list
    )
    label: HlirLabel

    current_block_cm: ContextManager[Block] | None = field(init=False, default=None)

    @property
    def lowest_scope(self) -> "Scope":
        return self.scope_stack[-1]

    def resolve_var(self, var_name: str) -> HlirVariable:
        for scope in reversed(self.scope_stack):
            try:
                return scope.resolve_var(var_name)
            except Int3MissingEntityError:
                pass
        else:
            raise Int3MissingEntityError(f"Unable to resolve var name {var_name}")

    def add_operation(self, operation: HlirBranch | HlirOperation):
        """Record an operation or branch on this block.

        This method will enforce some variable naming norms. Namely, variable names will
        attempt to be resolved in the current scope.

        """
        # Validate that all of the operation's variables are resolvable within this block's
        # scope stack.
        for var in operation.args:
            if not isinstance(var, (HlirIntVariable, HlirBytesVariable)):
                continue

            try:
                self.resolve_var(var.name)
            except Int3MissingEntityError as e:
                raise Int3MissingEntityError(
                    f"Operation {operation} is using unnamed variable"
                ) from e

        self.operations.append(operation)

    def to_str(self, indent: int = 0) -> str:
        indent_str = self.indent_str(indent)
        block_text = f"{indent_str}{self.label}:\n"

        for operation in self.operations:
            block_text += operation.to_str(indent=indent + 1)
            block_text += "\n"

        return block_text

    def __enter__(self) -> Block:
        self.current_block_cm = self.compiler.current_func._current_block_as(self)
        return self.current_block_cm.__enter__()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if self.current_block_cm is None:
            raise RuntimeError("This should be unreachable!")
        else:
            self.current_block_cm.__exit__(None, None, None)
            self.current_block_cm = None
