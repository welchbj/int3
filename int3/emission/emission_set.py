from dataclasses import dataclass, field

from int3.context import Context

from .emission import Emission


@dataclass(frozen=True)
class EmissionSet:
    """A set of emissions that achieve the same end state."""

    ctx: Context

    emissions: set = field(default_factory=set)

    def __post_init__(self):
        self.emissions = set(self.emissions)

    def shortest(self) -> Emission:
        """Return the shortest Emission in this set."""
        # TODO: Error on empty set.
        # TODO: Return the shortest by length.
