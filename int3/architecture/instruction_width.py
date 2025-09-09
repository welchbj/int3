from enum import Enum, auto


class InstructionWidth(Enum):
    """Fixed or variable instruction width."""

    Variable = auto()
    Fixed = auto()
