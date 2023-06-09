from dataclasses import dataclass, field

from int3.register import Register


@dataclass(frozen=True)
class Emission:
    """An assembly emission, with annotated side effects."""

    data: bytes

    clobbered_registers: set[Register] = field(default_factory=set)
