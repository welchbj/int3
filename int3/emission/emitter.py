import functools
from dataclasses import dataclass
from typing import Iterable

from int3.context import Context
from int3.errors import Int3SatError
from int3.gadgets import Gadget
from int3.registers import IntImmediate
from int3.strategy import Strategy


@dataclass
class Emitter:
    ctx: Context

    def choose(self, gadget_iter: Iterable[Gadget]) -> Gadget:
        """Choose gadget based on bad byte constraints and the emission strategy."""
        filtered_gadgets = []

        for gadget in gadget_iter:
            if not gadget.is_okay(self.ctx):
                continue

            if self.ctx.strategy == Strategy.GenerationSpeed:
                return gadget
            else:
                filtered_gadgets.append(gadget)

        if not filtered_gadgets:
            raise Int3SatError("Unable to identify any potential gadgets")

        assembled_len_wrapper = functools.partial(Gadget.assembled_len, ctx=self.ctx)
        return min(filtered_gadgets, key=assembled_len_wrapper)
