from int3.gadgets import Gadget
from int3.registers import x86_64Registers

from ._intel_emitter_mixin import IntelEmitterMixin


class x86_64Emitter(IntelEmitterMixin[x86_64Registers]):

    def literal_syscall(self) -> Gadget:
        return Gadget("syscall")
