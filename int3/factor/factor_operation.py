from enum import Enum, auto


class FactorOperation(Enum):
    """Supported factor operations."""

    Init = auto()

    Add = auto()
    Sub = auto()
    Xor = auto()
    Neg = auto()
