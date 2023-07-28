from dataclasses import dataclass, field

from .gadget import Gadget


@dataclass(frozen=True)
class MultiGadget(Gadget):
    gadgets: tuple[Gadget, ...] = field(default_factory=tuple)

    def __init__(self, *gadgets: Gadget):
        object.__setattr__(self, "gadgets", tuple(gadgets))

        super().__init__(assembly="\n".join(str(g) for g in self.gadgets))
