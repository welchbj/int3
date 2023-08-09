from int3.gadgets import Gadget
from int3.registers import x86Registers

from ._intel_emitter_mixin import IntelEmitterMixin


class x86Emitter(IntelEmitterMixin[x86Registers]):
    ...
