from int3.gadget import Gadget
from int3.registers import Immediate, IntImmediate, Registers

from .architecture_emitter import ArchitectureEmitter


class SemanticEmitter(ArchitectureEmitter[Registers]):
    def mov(self, dst: Registers, src: Registers | IntImmediate) -> Gadget:
        # See if naive solution works.
        if (gadget := self.literal_mov(dst, src)).is_okay(self.ctx):
            return gadget

        # When a bad byte is in the immediate operand, we can try to break apart
        # the operand into multiple operations of the same type.
        # TODO

        # When a bad byte is in the register operand, we can piece together
        # operations on multiple available registers.
        # TODO

        # When a bad byte is in the operation itself, we can attempt to piece
        # together multiple operations in to the equivalent operation.
        # TODO

        # TODO
        return Gadget("__invalid__")

    def load(self, dst: Registers, src_ptr: Registers, offset: int = 0) -> Gadget:
        # TODO
        return Gadget("__invalid__")

    def push(self, value: Registers | Immediate) -> Gadget:
        # TODO
        return Gadget("__invalid__")

    def pop(self, result: Registers | None = None) -> Gadget:
        # TODO
        return Gadget("__invalid__")

    def add(self, dst: Registers, operand: Registers | IntImmediate) -> Gadget:
        # TODO
        return Gadget("__invalid__")

    def sub(self, dst: Registers, operand: Registers | IntImmediate) -> Gadget:
        # TODO
        return Gadget("__invalid__")

    def xor(self, dst: Registers, operand: Registers | IntImmediate) -> Gadget:
        # TODO
        return Gadget("__invalid__")

    def neg(self, dst: Registers) -> Gadget:
        # TODO
        return Gadget("__invalid__")

    def call(self, target: Registers) -> Gadget:
        # TODO
        return Gadget("__invalid__")

    def breakpoint(self) -> Gadget:
        return self.literal_breakpoint()

    # TODO: Shifts?

    def label(self, name: str) -> Gadget:
        return self.literal_label(name)
