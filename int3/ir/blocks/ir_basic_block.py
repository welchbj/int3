from __future__ import annotations

from dataclasses import dataclass, field
from types import TracebackType

from ..variables import IrVar


@dataclass
class IrBasicBlock:
    predecessors: list[IrBasicBlock] = field(default_factory=list)
    successors: list[IrBasicBlock] = field(default_factory=list)

    local_vars: list[IrVar] = field(default_factory=list)

    def __enter__(self) -> IrBasicBlock:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        pass
