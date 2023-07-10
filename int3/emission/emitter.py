from dataclasses import dataclass

from int3.context import Context
from int3.gadget import Gadget
from int3.registers import IntImmediate

# XXX
# Situations we should be capable of working around:
# - When a bad byte is in an operation, we can use other equivalent operations.
# - When a bad byte is in an immediate, we can use z3 to work around this.
#   -- We need to tell z3 which mathematical operators are available.
# - When a register operand is free, we can iterate over available registers.
#
# - It seems like our current strategy won't support bad bytes in jump offsets.
#   -- Perhaps we can try adding in nops?


@dataclass
class Emitter:
    ctx: Context

    def choose(self, *gadgets: Gadget | str):
        """Choose gadget based on bad byte constraints and the emission strategy."""
        for gadget in gadgets:
            if isinstance(gadget, str):
                gadget = Gadget(gadget)

            if gadget.is_okay(self.ctx):
                # TODO
                pass

        # TODO
