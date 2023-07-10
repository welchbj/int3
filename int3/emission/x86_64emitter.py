from int3.gadget import Gadget
from int3.registers import Immediate, IntImmediate, x86_64Registers

from .architecture_emitter import ArchitectureEmitter


class x86_64Emitter(ArchitectureEmitter[x86_64Registers]):
    def literal_mov(
        self, dst: x86_64Registers, src: x86_64Registers | IntImmediate
    ) -> Gadget:
        # TODO
        return Gadget("")

    def literal_load(
        self, dst: x86_64Registers, src_ptr: x86_64Registers, offset: int = 0
    ) -> Gadget:
        # TODO
        return Gadget("")

    def literal_push(self, value: x86_64Registers | Immediate) -> Gadget:
        # TODO
        return Gadget("")

    def literal_pop(self, result: x86_64Registers | None = None) -> Gadget:
        # TODO
        return Gadget("")

    def literal_add(
        self, dst: x86_64Registers, operand: x86_64Registers | IntImmediate
    ) -> Gadget:
        # TODO
        return Gadget("")

    def literal_sub(
        self, dst: x86_64Registers, operand: x86_64Registers | IntImmediate
    ) -> Gadget:
        # TODO
        return Gadget("")

    def literal_xor(
        self, dst: x86_64Registers, operand: x86_64Registers | IntImmediate
    ) -> Gadget:
        # TODO
        return Gadget("")

    def literal_neg(self, dst: x86_64Registers) -> Gadget:
        # TODO
        return Gadget("")

    def literal_call(self, target: x86_64Registers) -> Gadget:
        # TODO
        return Gadget("")

    def literal_breakpoint(self) -> Gadget:
        return Gadget("int3")

    # TODO: Shifts?
