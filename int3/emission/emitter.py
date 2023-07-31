import functools
from dataclasses import dataclass, field
from typing import Iterable

from int3.context import Context
from int3.errors import Int3SatError
from int3.gadgets import Gadget
from int3.strategy import Strategy


@dataclass
class Emitter:
    ctx: Context

    ledger: str = field(init=False, default="")

    def choose(self, gadget_iter: Iterable[Gadget]) -> Gadget:
        """Choose a gadget based on bad byte constraints and the strategy."""
        filtered_gadgets = []

        for gadget in gadget_iter:
            if not gadget.is_okay(self.ctx):
                continue

            if self.ctx.strategy == Strategy.GenerationSpeed:
                # Short circuit for the first valid gadget.
                return gadget
            else:
                filtered_gadgets.append(gadget)

        if not filtered_gadgets:
            raise Int3SatError("Unable to identify any potential gadgets")

        assembled_len_wrapper = functools.partial(Gadget.assembled_len, ctx=self.ctx)
        return min(filtered_gadgets, key=assembled_len_wrapper)

    def emit(self, gadget: Gadget):
        """Record this gadget on this Emitter's ledger of assembly."""
        self.ledger += str(gadget)
        self.ledger += "\n"

    def choose_and_emit(self, gadget_iter: Iterable[Gadget]):
        self.emit(self.choose(gadget_iter))

    def __str__(self) -> str:
        return self.ledger
