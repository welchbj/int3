from dataclasses import dataclass


@dataclass
class StackScope:
    stack_change: int = 0
    is_corrupted: bool = False
