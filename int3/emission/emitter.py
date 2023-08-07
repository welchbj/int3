import functools
import random
from dataclasses import dataclass, field
from typing import Iterable, TypeVar

from int3.context import Context
from int3.errors import Int3SatError
from int3.gadgets import Gadget
from int3.strategy import Strategy

T = TypeVar("T")


@dataclass
class Emitter:
    ctx: Context

    ledger: str = field(init=False, default="")

    def choose(self, item_iter: Iterable[T]) -> T:
        """Choose an item from an iterable according to the active strategy..

        For iterables of Gadgets, choices will be limited to those that meet
        bad byte constraints.

        """
        is_gadget_seq = False
        filtered_items = []

        for item in item_iter:
            if isinstance(item, Gadget):
                is_gadget_seq = True

                if not item.is_okay(self.ctx):
                    continue

            if self.ctx.strategy == Strategy.GenerationSpeed:
                # Short circuit for the first valid gadget.
                return item
            else:
                filtered_items.append(item)

        if not filtered_items:
            if is_gadget_seq:
                msg = "Unable to identify any satisfactory gadgets"
            else:
                msg = "Unable to identify a suitable choice"

            raise Int3SatError(msg)

        if self.ctx.strategy == Strategy.Random:
            return random.choice(filtered_items)
        elif is_gadget_seq:
            assembled_len_wrapper = functools.partial(
                Gadget.assembled_len, ctx=self.ctx
            )
            return min(filtered_items, key=assembled_len_wrapper)
        else:
            # Default to just picking the first one.
            return filtered_items[0]

    def emit(self, gadget: Gadget):
        """Record this gadget on this Emitter's ledger of assembly."""
        self.ledger += str(gadget)
        self.ledger += "\n"

    def choose_and_emit(self, gadget_iter: Iterable[Gadget]):
        self.emit(self.choose(gadget_iter))

    def __str__(self) -> str:
        return self.ledger
