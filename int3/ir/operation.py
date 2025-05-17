from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .variable import IrVariable


class IrOperator(Enum):
    Mov = auto()
    Add = auto()
    Sub = auto()
    Xor = auto()
    Syscall = auto()


@dataclass
class IrOperation:
    operator: IrOperator
    result: "IrVariable"
    args: list["IrVariable"]

    def __str__(self) -> str:
        text = f"{self.result} = "
        text += self.operator.name
        text += "("
        text += ", ".join(str(arg) for arg in self.args)
        text += ")"
        return text
