from __future__ import annotations

from dataclasses import dataclass

from int3.architectures import Architecture, Architectures
from int3.platforms import Platform, Platforms
from int3.registers import IntImmediate

__all__ = ["Context"]


@dataclass(frozen=True)
class Context:
    architecture: Architecture
    platform: Platform

    bad_bytes: bytes = b""
    vma: int = 0
    usable_stack: bool = True

    @staticmethod
    def from_host(
        bad_bytes: bytes = b"",
        vma: int = 0,
        usable_stack: bool = True,
    ) -> Context:
        return Context(
            architecture=Architectures.from_host(),
            platform=Platforms.from_host(),
            bad_bytes=bad_bytes,
            vma=vma,
            usable_stack=usable_stack,
        )

    def is_okay_immediate(self, imm: IntImmediate, width: int | None = None) -> bool:
        """Check whether a specified immediate is invalid for use.

        For example, immediates with bad bytes will return False.

        """
        return not any(b in self.architecture.pack(imm, width=width) for b in self.bad_bytes)
