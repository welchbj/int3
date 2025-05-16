from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .variable import IrVariable


class IrBranchOperator(Enum):
    LessThan = auto()
    # TODO


LABEL_UNSET = "<<unset>>"


@dataclass
class IrBranch:
    operator: IrBranchOperator
    args: list["IrVariable"]

    if_target: str = LABEL_UNSET
    else_target: str = LABEL_UNSET

    def set_targets(self, if_target: str, else_target: str):
        self.if_target = if_target
        self.else_target = else_target

    def __str__(self) -> str:
        # TODO
        return "branch"
