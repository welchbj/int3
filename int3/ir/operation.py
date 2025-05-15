from dataclasses import dataclass
from enum import Enum, auto


class IrOperator(Enum):
    Add = auto()
    Sub = auto()
    Xor = auto()
    Syscall = auto()


@dataclass
class IrOperation:
    # TODO
    ...
