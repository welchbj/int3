from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING, Optional, Union

from int3._interfaces import PrintableIr

from .hlir_label import HlirLabel

if TYPE_CHECKING:
    from .hlir_variable import HlirAnyType, HlirVariable


class HlirOperator(Enum):
    Mov = auto()
    Add = auto()
    Sub = auto()
    Xor = auto()
    Syscall = auto()
    Jump = auto()


@dataclass
class HlirOperation(PrintableIr):
    operator: HlirOperator
    result: Optional["HlirVariable"]
    args: list[Union["HlirAnyType", "HlirLabel"]]

    def to_str(self, indent: int = 0) -> str:
        text = self.indent_str(indent)
        if self.result is not None:
            text += f"{self.result} = "
        text += self.operator.name
        text += "("
        text += ", ".join(str(arg) for arg in self.args)
        text += ")"
        return text
