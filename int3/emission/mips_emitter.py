from int3.gadgets import Gadget, MultiGadget
from int3.immediates import IntImmediate
from int3.registers import Registers

from .architecture_emitter import ArchitectureEmitter


class MipsEmitter(ArchitectureEmitter[Registers]):
    def literal_mov(self, dst: Registers, src: Registers | IntImmediate) -> Gadget:
        if isinstance(src, IntImmediate):
            return Gadget(f"li {dst}, {hex(src)}")
        else:
            return Gadget(f"move {dst}, {src}")

    # TODO: Need type for Label.
    def literal_load(
        self, dst: Registers, src_ptr: Registers, offset: int = 0
    ) -> Gadget:
        ...

    def literal_store(
        self, dst: Registers, src: Registers | IntImmediate, offset: int = 0
    ) -> Gadget:
        ...

    def literal_push(self, value: Registers | IntImmediate) -> Gadget:
        if isinstance(value, IntImmediate):
            return MultiGadget(
                # TODO
            )
        else:
            return MultiGadget(
                self.literal_add("$sp", -4),
                self.literal_store("$sp", value),
            )

    def literal_pop(self, result: Registers) -> Gadget:
        ...

    def literal_add(self, dst: Registers, operand: Registers | IntImmediate) -> Gadget:
        ...

    def literal_sub(self, dst: Registers, operand: Registers | IntImmediate) -> Gadget:
        ...

    def literal_xor(self, dst: Registers, operand: Registers | IntImmediate) -> Gadget:
        ...

    def literal_neg(self, dst: Registers) -> Gadget:
        ...

    def literal_call(self, target: Registers) -> Gadget:
        ...

    def literal_breakpoint(self) -> Gadget:
        return Gadget("break")

    def literal_label(self, name: str) -> Gadget:
        return Gadget(f"{name}: ")

