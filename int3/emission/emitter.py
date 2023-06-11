from dataclasses import dataclass, field

from int3.context import Context
from int3.assembly import assemble


@dataclass
class Emitter:
    ctx: Context

    assembly: str = field(init=False, default="")

    def __bytes__(self) -> bytes:
        return assemble(ctx=self.ctx, assembly=self.assembly)
