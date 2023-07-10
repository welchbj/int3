from int3.gadget import Gadget
from int3.registers import Immediate, IntImmediate, x86Registers

from .architecture_emitter import ArchitectureEmitter


class x86Emitter(ArchitectureEmitter[x86Registers]):
    def literal_mov(
        self, dst: x86Registers, src: x86Registers | IntImmediate
    ) -> Gadget:
        src_str = hex(src) if isinstance(src, IntImmediate) else src
        return Gadget(f"mov {dst}, {src_str}")

    def literal_load(
        self, dst: x86Registers, src_ptr: x86Registers, offset: int = 0
    ) -> Gadget:
        if offset == 0:
            load_addr = f"[{src_ptr}]"
        else:
            load_addr = f"[{src_ptr}+{hex(offset)}]"

        return Gadget(f"mov {dst}, {load_addr}")

    def literal_push(self, value: x86Registers | Immediate) -> Gadget:
        if isinstance(value, bytes):
            raise NotImplementedError("bytes immediates not yet supported")

        value_str = hex(value) if isinstance(value, IntImmediate) else value
        return Gadget(f"push {value_str}")

    def literal_pop(self, result: x86Registers | None = None) -> Gadget:
        if result is None:
            # TODO
            raise NotImplementedError("Automatic register selection not implemented")

        return Gadget(f"pop {result}")

    def literal_add(
        self, dst: x86Registers, operand: x86Registers | IntImmediate
    ) -> Gadget:
        operand_str = hex(operand) if isinstance(operand, IntImmediate) else operand
        return Gadget(f"add {dst}, {operand_str}")

    def literal_sub(
        self, dst: x86Registers, operand: x86Registers | IntImmediate
    ) -> Gadget:
        operand_str = hex(operand) if isinstance(operand, IntImmediate) else operand
        return Gadget(f"sub {dst}, {operand_str}")

    def literal_xor(
        self, dst: x86Registers, operand: x86Registers | IntImmediate
    ) -> Gadget:
        operand_str = hex(operand) if isinstance(operand, IntImmediate) else operand
        return Gadget(f"xor {dst}, {operand_str}")

    def literal_neg(self, dst: x86Registers) -> Gadget:
        return Gadget(f"neg {dst}")

    def literal_call(self, target: x86Registers) -> Gadget:
        return Gadget(f"call {target}")

    def literal_breakpoint(self) -> Gadget:
        return Gadget("int3")
