from __future__ import annotations

from dataclasses import dataclass, field

from int3.context import Context


@dataclass(frozen=True)
class Gadget:
    assembly: str

    # TODO: Determine if we need the below.
    template: str = "@@"
    parameters: list[str] = field(default_factory=list)

    def is_okay(self, ctx: Context) -> bool:
        """Returns whether this gadget is okay for the provided context."""
        # TODO
        return False

    def __str__(self) -> str:
        return self.assembly
