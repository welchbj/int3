from dataclasses import dataclass

from ..types import IrType


@dataclass
class IrVar:
    type_: IrType
