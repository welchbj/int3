from dataclasses import dataclass

from int3.register import Register

from .emission import Emission
from .emission_set import EmissionSet
from .emitter import Emitter


@dataclass
class x86Emitter(Emitter):
    """An emitter for 32-bit x86 assembly."""

    # TODO: Should the below (start of an) interface be placed in something like an
    #       ArchitectureEmitter ABC?

    def mov(self, dst: Register, src: Register) -> EmissionSet:
        # TODO
        pass

    def load(self, dst: Register, src_ptr: Register, offset: int = 0) -> EmissionSet:
        # TODO
        pass

    def clear(self, reg: Register) -> EmissionSet:
        # TODO
        pass

    def push(self, value: Register | int) -> EmissionSet:
        # TODO
        pass

    def pop(self, result: Register) -> EmissionSet:
        # TODO
        pass
