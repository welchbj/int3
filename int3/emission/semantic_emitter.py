from typing import Generic

from int3.gadget import Gadget
from int3.registers import Immediate, IntImmediate, Registers

from .architecture_emitter import ArchitectureEmitter


class SemanticEmitter(ArchitectureEmitter[Registers], Generic[Registers]):
    def mov(self, dst: Registers, src: Registers | IntImmediate) -> Gadget:
        # TODO
        return Gadget("")

    def load(self, dst: Registers, src_ptr: Registers, offset: int = 0) -> Gadget:
        # TODO
        return Gadget("")

    def push(self, value: Registers | Immediate) -> Gadget:
        # TODO
        return Gadget("")

    def pop(self, result: Registers | None = None) -> Gadget:
        # TODO
        return Gadget("")

    def add(self, dst: Registers, operand: Registers | IntImmediate) -> Gadget:
        # TODO
        return Gadget("")

    def sub(self, dst: Registers, operand: Registers | IntImmediate) -> Gadget:
        # TODO
        return Gadget("")

    def xor(self, dst: Registers, operand: Registers | IntImmediate) -> Gadget:
        # TODO
        return Gadget("")

    def neg(self, dst: Registers) -> Gadget:
        # TODO
        return Gadget("")

    def call(self, target: Registers) -> Gadget:
        # TODO
        return Gadget("")

    def breakpoint(self) -> Gadget:
        return super().breakpoint()

    # TODO: Shifts?

    def label(self, name: str) -> Gadget:
        return Gadget(f"{name}: ")
