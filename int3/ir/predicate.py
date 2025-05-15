from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .variable import IrVariable


class IrPredicateOperator(Enum):
    LessThan = auto()
    # TODO


@dataclass
class IrPredicate:
    operator: IrPredicateOperator
    args: list["IrVariable"]
