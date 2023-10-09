from int3.gadgets import Gadget, MultiGadget
from int3.immediates import IntImmediate
from int3.labels import Label
from int3.registers import MipsRegisters

from .architecture_emitter import ArchitectureEmitter


class MipsEmitter(ArchitectureEmitter[MipsRegisters]):
    def literal_mov(
        self, dst: MipsRegisters, src: MipsRegisters | IntImmediate
    ) -> Gadget:
        if isinstance(src, IntImmediate):
            return Gadget(f"li {dst}, {hex(src)}")
        else:
            return Gadget(f"move {dst}, {src}")

    def literal_load(
        self, dst: MipsRegisters, src_ptr: MipsRegisters, offset: int = 0
    ) -> Gadget:
        # TODO
        return Gadget("__invalid__")

    def literal_store(
        self, dst: MipsRegisters, src: MipsRegisters | IntImmediate, offset: int = 0
    ) -> Gadget:
        # TODO
        return Gadget("__invalid__")

    def literal_push(self, value: MipsRegisters | IntImmediate) -> Gadget:
        if isinstance(value, IntImmediate):
            return MultiGadget(
                # TODO
            )
        else:
            return MultiGadget(
                self.literal_add("$sp", -4),
                self.literal_store("$sp", value),
            )

    def literal_pop(self, result: MipsRegisters) -> Gadget:
        # TODO
        return Gadget("__invalid__")

    def literal_add(
        self, dst: MipsRegisters, operand: MipsRegisters | IntImmediate
    ) -> Gadget:
        # TODO
        return Gadget("__invalid__")

    def literal_sub(
        self, dst: MipsRegisters, operand: MipsRegisters | IntImmediate
    ) -> Gadget:
        # TODO
        return Gadget("__invalid__")

    def literal_xor(
        self, dst: MipsRegisters, operand: MipsRegisters | IntImmediate
    ) -> Gadget:
        # TODO
        return Gadget("__invalid__")

    def literal_neg(self, dst: MipsRegisters) -> Gadget:
        # TODO
        return Gadget("__invalid__")

    def literal_call(self, target: MipsRegisters | Label) -> Gadget:
        # TODO
        return Gadget("__invalid__")

    def literal_jump(self, target: MipsRegisters | Label | IntImmediate) -> Gadget:
        # TODO
        return Gadget("__invalid__")

    def literal_je(
        self, operand_one: MipsRegisters, operand_two: MipsRegisters, target: Label
    ) -> Gadget:
        # TODO
        return Gadget("__invalid__")

    def literal_jne(
        self, operand_one: MipsRegisters, operand_two: MipsRegisters, target: Label
    ) -> Gadget:
        # TODO
        return Gadget("__invalid__")

    def literal_jgt(
        self, operand_one: MipsRegisters, operand_two: MipsRegisters, target: Label
    ) -> Gadget:
        # TODO
        return Gadget("__invalid__")

    def literal_jlt(
        self, operand_one: MipsRegisters, operand_two: MipsRegisters, target: Label
    ) -> Gadget:
        # TODO
        return Gadget("__invalid__")

    def literal_jge(
        self, operand_one: MipsRegisters, operand_two: MipsRegisters, target: Label
    ) -> Gadget:
        # TODO
        return Gadget("__invalid__")

    def literal_jle(
        self, operand_one: MipsRegisters, operand_two: MipsRegisters, target: Label
    ) -> Gadget:
        # TODO
        return Gadget("__invalid__")

    def literal_breakpoint(self) -> Gadget:
        return Gadget("break")

    def literal_ret(self) -> Gadget:
        # TODO
        return Gadget("__invalid__")
