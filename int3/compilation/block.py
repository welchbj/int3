from __future__ import annotations

from dataclasses import dataclass, field
from types import TracebackType
from typing import TYPE_CHECKING, ContextManager

from int3.errors import Int3MissingEntityError
from int3.ir import IrOperation, IrVariable

if TYPE_CHECKING:
    from .compiler import Compiler
    from .scope import Scope


@dataclass
class Block:
    compiler: "Compiler"
    scope_stack: list["Scope"]
    operations: list[IrOperation] = field(init=False, default_factory=list)

    current_block_cm: ContextManager[Block] | None = field(init=False, default=None)

    @property
    def lowest_scope(self) -> "Scope":
        return self.scope_stack[-1]

    def resolve_var(self, var_name: str) -> IrVariable:
        for scope in reversed(self.scope_stack):
            try:
                return scope.resolve_var(var_name)
            except Int3MissingEntityError:
                pass
        else:
            raise Int3MissingEntityError(f"Unable to resolve var name {var_name}")

    def __str__(self) -> str:
        block_text = ""

        for operation in self.operations:
            block_text += str(operation)
            block_text += "\n"

        return block_text

    def __enter__(self) -> Block:
        self.current_block_cm = self.compiler.current_block_as(self)
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
