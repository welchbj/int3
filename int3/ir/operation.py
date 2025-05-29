from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING

from int3._interfaces import PrintableIr

if TYPE_CHECKING:
    from .variable import AnyIrType, IrVariable


class IrOperator(Enum):
    Mov = auto()
    Add = auto()
    Sub = auto()
    Xor = auto()
    Syscall = auto()
    Birth = auto()
    Kill = auto()
    Lock = auto()


@dataclass
class IrOperation(PrintableIr):
    operator: IrOperator
    result: "IrVariable"
    args: list["AnyIrType"]

    def to_str(self, indent: int = 0) -> str:
        indent_str = self.indent_str(indent)

        text = f"{indent_str}{self.result} = "
        text += self.operator.name
        text += "("
        text += ", ".join(str(arg) for arg in self.args)
        text += ")"
        return text
