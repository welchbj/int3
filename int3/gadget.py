from __future__ import annotations

from dataclasses import dataclass, field

from int3.assembly import assemble
from int3.context import Context
from int3.errors import Int3WrappedKeystoneError


@dataclass(frozen=True)
class Gadget:
    assembly: str

    def is_okay(self, ctx: Context) -> bool:
        """Returns whether this gadget is okay for the provided context."""
        try:
            assembled_bytes = self.assembled(ctx)
        except Int3WrappedKeystoneError as e:
            # XXX: How will we address jumps that can't be assembled without more context?
            return False
        else:
            return not any(b in assembled_bytes for b in ctx.bad_bytes)

    def assembled(self, ctx: Context) -> bytes:
        return assemble(ctx=ctx, assembly=self.assembly)

    def __str__(self) -> str:
        return self.assembly
