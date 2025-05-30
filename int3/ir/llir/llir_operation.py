from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING

from int3._interfaces import PrintableIr

if TYPE_CHECKING:
    from .llir_types import LlirAnyType
    from .llir_virtual_register import LlirVirtualRegister


class LlirOperator(Enum):
    Mov = auto()
    Birth = auto()
    Kill = auto()
    Lock = auto()
    Syscall = auto()


@dataclass(frozen=True)
class LlirOperation(PrintableIr):
    operator: LlirOperator
    result: "LlirVirtualRegister"
    args: tuple["LlirAnyType"]

    def to_str(self, indent: int = 0) -> str:
        indent_str = self.indent_str(indent)

        text = f"{indent_str}{self.result} = "
        text += self.operator.name
        text += "("
        text += ", ".join(str(arg) for arg in self.args)
        text += ")"
        return text
