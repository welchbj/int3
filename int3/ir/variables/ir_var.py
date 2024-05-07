from __future__ import annotations

from dataclasses import dataclass, field

from ..operations import IrOperation
from ..types import IrType


@dataclass
class IrVar:
    type_: IrType

    operation_refs: list[IrOperation] = field(init=False, default_factory=list)
