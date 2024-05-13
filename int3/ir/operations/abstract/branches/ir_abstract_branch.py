from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..ir_abstract_operation import IrAbstractOperation

if TYPE_CHECKING:
    from ....blocks import IrBasicBlock


@dataclass
class IrAbstractBranch(IrAbstractOperation):
    taken: "IrBasicBlock"
    not_taken: "IrBasicBlock"
