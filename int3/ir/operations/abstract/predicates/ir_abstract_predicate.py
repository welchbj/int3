from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..ir_abstract_operation import IrAbstractOperation

if TYPE_CHECKING:
    from ....variables import IrVar


@dataclass
class IrAbstractPredicate(IrAbstractOperation):
    left_operand: "IrVar"
    right_operand: "IrVar"
