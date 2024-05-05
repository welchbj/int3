from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class IrBasicBlock:
    predecessors: list[IrBasicBlock] = field(default_factory=list)
    successors: list[IrBasicBlock] = field(default_factory=list)

    xrefs: dict[str, IrBasicBlock] = field(default_factory=dict)

    # TODO: Need to keep track of variables and allocated stack space.
