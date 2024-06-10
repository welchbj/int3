from __future__ import annotations

from dataclasses import dataclass

from .ir_type import IrType


@dataclass(frozen=True)
class IrBytesType(IrType):
    pass
