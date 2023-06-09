from dataclasses import dataclass, field

from int3.context import Context


@dataclass
class Emitter:
    ctx: Context

    ledger: bytes = field(init=False, default=b"")

    def __bytes__(self) -> bytes:
        return self.ledger

    # TODO: Context manager for locking registers, etc.
