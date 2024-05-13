from __future__ import annotations

from dataclasses import dataclass, field
from types import TracebackType
from typing import ContextManager

from int3.compilation.compiler_scope import CompilerScope

from ..operations import IrAbstractOperation


@dataclass
class IrBasicBlock:
    cc_scope: CompilerScope

    operations: list[IrAbstractOperation] = field(default_factory=list)
    incoming_edges: list[IrBasicBlock] = field(default_factory=list)
    outgoing_edges: list[IrBasicBlock] = field(default_factory=list)

    active_bb_cm: ContextManager[IrBasicBlock] | None = field(init=False, default=None)

    def add_operation(self, op: IrAbstractOperation):
        # TODO: Checking of variables against cc_scope?
        self.operations.append(op)

    def add_incoming_edge(self, other_bb: IrBasicBlock):
        # TODO: Should we error on circular references?
        self.incoming_edges.append(other_bb)

    def add_outgoing_edge(self, other_bb: IrBasicBlock):
        # TODO: Should we error on circular references?
        self.outgoing_edges.append(other_bb)

    def __enter__(self) -> IrBasicBlock:
        self.active_bb_cm = self.cc_scope.cc.active_bb_cm(self)
        return self.active_bb_cm.__enter__()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if self.active_bb_cm is None:
            raise RuntimeError("This should be unreachable!")
        else:
            self.active_bb_cm.__exit__(None, None, None)
            self.active_bb_cm = None
