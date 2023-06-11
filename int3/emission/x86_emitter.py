from dataclasses import dataclass

from int3.registers import Immediate, IntImmediate, x86Registers

from .architecture_emitter import ArchitectureEmitter


class x86Emitter(ArchitectureEmitter[x86Registers]):
    def mov(self, dst: x86Registers, src: x86Registers):
        # TODO
        pass

    def load(
        self, dst: x86Registers, src_ptr: x86Registers, offset: int = 0
    ) -> x86Registers:
        # TODO
        return "eax"

    def clear(self, reg: x86Registers):
        # TODO
        pass

    def push(self, value: x86Registers | Immediate):
        # TODO
        pass

    def pop(self, result: x86Registers | None = None) -> x86Registers:
        # TODO
        return "eax"

    def add(self, dst: x86Registers, operand: x86Registers | IntImmediate):
        # TODO
        pass

    def sub(self, dst: x86Registers, operand: x86Registers | IntImmediate):
        # TODO
        pass

    def xor(self, dst: x86Registers, operand: x86Registers | IntImmediate):
        # TODO
        pass

    def neg(self, dst: x86Registers):
        # TODO
        pass

    def call(self, target: x86Registers):
        # TODO
        pass
