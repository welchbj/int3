from int3.gadgets import Gadget
from int3.immediates import Immediate, IntImmediate
from int3.registers import Registers

from .architecture_emitter import ArchitectureEmitter


class IntelEmitterMixin(ArchitectureEmitter[Registers]):
    def literal_mov(
        self, dst: Registers, src: Registers | IntImmediate
    ) -> Gadget:
        src_str = hex(src) if isinstance(src, IntImmediate) else src
        return Gadget(f"mov {dst}, {src_str}")

    def literal_load(
        self, dst: Registers, src_ptr: Registers, offset: int = 0
    ) -> Gadget:
        if offset == 0:
            load_addr = f"[{src_ptr}]"
        else:
            load_addr = f"[{src_ptr}+{hex(offset)}]"

        return Gadget(f"mov {dst}, {load_addr}")

    def literal_push(self, value: Registers | Immediate) -> Gadget:
        if isinstance(value, bytes):
            raise NotImplementedError("bytes immediates not yet supported")

        value_str = hex(value) if isinstance(value, IntImmediate) else value
        return Gadget(f"push {value_str}")

    def literal_pop(self, result: Registers) -> Gadget:
        return Gadget(f"pop {result}")

    def literal_add(
        self, dst: Registers, operand: Registers | IntImmediate
    ) -> Gadget:
        operand_str = hex(operand) if isinstance(operand, IntImmediate) else operand
        return Gadget(f"add {dst}, {operand_str}")

    def literal_sub(
        self, dst: Registers, operand: Registers | IntImmediate
    ) -> Gadget:
        operand_str = hex(operand) if isinstance(operand, IntImmediate) else operand
        return Gadget(f"sub {dst}, {operand_str}")

    def literal_xor(
        self, dst: Registers, operand: Registers | IntImmediate
    ) -> Gadget:
        operand_str = hex(operand) if isinstance(operand, IntImmediate) else operand
        return Gadget(f"xor {dst}, {operand_str}")

    def literal_neg(self, dst: Registers) -> Gadget:
        return Gadget(f"neg {dst}")

    def literal_call(self, target: Registers) -> Gadget:
        return Gadget(f"call {target}")

    def literal_breakpoint(self) -> Gadget:
        return Gadget("int3")
