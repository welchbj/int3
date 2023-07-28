from dataclasses import dataclass, field
from typing import Any

from int3.gadgets import Gadget


@dataclass
class Builder:
    assembly: str = field(init=False, default="")

    def __add__(self, other: Any):
        if not isinstance(other, Gadget):
            return NotImplemented
        else:
            self.assembly += str(other)
            self.assembly += "\n"

        return self

    def __str__(self) -> str:
        return self.assembly
