from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .variable import IrVariable


class IrOperator(Enum):
    Add = auto()
    Sub = auto()
    Xor = auto()
    Syscall = auto()


@dataclass
class IrOperation:
    operator: IrOperator
    args: list["IrVariable"]

    def __str__(self) -> str:
        # TODO
        pass
