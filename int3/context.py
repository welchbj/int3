from __future__ import annotations

from dataclasses import dataclass

from int3.architectures import Architecture, Architectures
from int3.immediates import IntImmediate
from int3.platforms import Platform, Platforms
from int3.strategy import Strategy


@dataclass(frozen=True)
class Context:
    architecture: Architecture
    platform: Platform

    strategy: Strategy = Strategy.CodeSize
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

    def is_okay_int_immediate(
        self, imm: IntImmediate, width: int | None = None
    ) -> bool:
        """Check whether a specified immediate is invalid for use.

        For example, immediates with bad bytes will return False.

        """

        # TODO: Each architecture should support encoding constraints as SAT
        #       expressions.

        return not any(
            b in self.architecture.pack(imm, width=width) for b in self.bad_bytes
        )

    def make_okay_int_immediate(self, width: int | None = None) -> int:
        if width is None:
            width = self.architecture.bit_size

        valid_bytes = list(set(range(0x100)) - set(self.bad_bytes))
        return self.architecture.unpack(
            bytes([valid_bytes[0] for _ in range(width // self.architecture.BITS_IN_A_BYTE)]),
            width=width,
        )
