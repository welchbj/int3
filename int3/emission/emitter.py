import functools
import random
from dataclasses import dataclass, field
from typing import Iterable, TypeVar

from int3.architectures import Architecture
from int3.context import Context
from int3.errors import Int3SatError
from int3.gadgets import Gadget
from int3.strategy import Strategy

from .stack_scope import StackScope

T = TypeVar("T")


def _stack_scopes_init():
    return [StackScope()]


@dataclass
class Emitter:
    ctx: Context

    ledger: str = field(init=False, default="")
    stack_scopes: list[StackScope] = field(
        init=False, default_factory=_stack_scopes_init
    )

    def choose(self, item_iter: Iterable[T], filter: bool = True) -> T:
        """Choose an item from an iterable according to the active strategy..

        For iterables of Gadgets, choices will be limited to those that meet
        bad byte constraints.

        """
        is_gadget_seq = False
        filtered_items = []

        for item in item_iter:
            if isinstance(item, Gadget):
                is_gadget_seq = True

                if filter and not item.is_okay(self.ctx):
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
            selected_gadget = min(filtered_items, key=assembled_len_wrapper)
            return selected_gadget
        else:
            # Default to just picking the first one.
            return filtered_items[0]

    def emit(self, gadget: Gadget):
        """Record this gadget on this Emitter's ledger of assembly."""
        self.current_stack_scope.stack_change += gadget.stack_change

        self.ledger += str(gadget)
        self.ledger += "\n"

    def choose_and_emit(self, gadget_iter: Iterable[Gadget]):
        self.emit(self.choose(gadget_iter))

    @property
    def arch(self) -> Architecture:
        return self.ctx.architecture

    @property
    def current_stack_scope(self) -> StackScope:
        return self.stack_scopes[-1]

    def __str__(self) -> str:
        return self.ledger
