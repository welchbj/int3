from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import ClassVar

from int3.assembly import assemble
from int3.context import Context
from int3.errors import Int3WrappedKeystoneError


@dataclass(frozen=True)
class Gadget:
    assembly: str

    LEN_CANNOT_ASSEMBLE: ClassVar[int] = 0xFFFFFFFF

    def is_okay(self, ctx: Context) -> bool:
        """Returns whether this gadget is okay for the provided context."""
        try:
            assembled_bytes = self.assembled(ctx)
        except Int3WrappedKeystoneError as e:
            logging.debug(f"keystone assembly failed: {e}")
            logging.debug(f"Problematic assembly:\n{self.assembly}")

            # XXX: How will we address jumps that can't be assembled without more context?
            return False
        else:
            return not any(b in assembled_bytes for b in ctx.bad_bytes)

    def assembled(self, ctx: Context) -> bytes:
        return assemble(ctx=ctx, assembly=self.assembly)

    def assembled_len(self, ctx: Context) -> int:
        try:
            return len(self.assembled(ctx=ctx))
        except Int3WrappedKeystoneError:
            return self.LEN_CANNOT_ASSEMBLE

    def __str__(self) -> str:
        return self.assembly
