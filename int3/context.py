from dataclasses import dataclass

from int3.architectures import Architecture
from int3.platforms import Platform
from int3.registers import IntImmediate

__all__ = ["Context"]


@dataclass(frozen=True)
class Context:
    architecture: Architecture
    platform: Platform

    bad_bytes: bytes = b""
    vma: int = 0
    usable_stack: bool = True

    def is_okay_immediate(self, imm: IntImmediate) -> bool:
        """Check whether a specified immediate is invalid for use.

        For example, immediates with bad bytes will return False.

        """
        return not any(b in self.architecture.pack(imm) for b in self.bad_bytes)
