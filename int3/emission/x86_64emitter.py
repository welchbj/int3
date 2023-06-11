from dataclasses import dataclass

from int3.registers import Immediate, IntImmediate, x86_64Registers

from .architecture_emitter import ArchitectureEmitter


class x86_64Emitter(ArchitectureEmitter[x86_64Registers]):
    def mov(self, dst: x86_64Registers, src: x86_64Registers):
        # TODO
        pass

    def load(self, dst: x86_64Registers, src_ptr: x86_64Registers, offset: int = 0):
        # TODO
        return "rax"

    def clear(self, reg: x86_64Registers):
        # TODO
        pass

    def push(self, value: x86_64Registers | Immediate):
        # TODO
        pass

    def pop(self, result: x86_64Registers | None = None) -> x86_64Registers:
        # TODO
        return "rax"

    def add(self, dst: x86_64Registers, operand: x86_64Registers | IntImmediate):
        # TODO
        pass

    def sub(self, dst: x86_64Registers, operand: x86_64Registers | IntImmediate):
        # TODO
        pass

    def xor(self, dst: x86_64Registers, operand: x86_64Registers | IntImmediate):
        # TODO
        pass

    def neg(self, dst: x86_64Registers):
        # TODO
        pass

    def call(self, target: x86_64Registers):
        # TODO
        pass
