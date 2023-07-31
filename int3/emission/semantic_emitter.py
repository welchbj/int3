from typing import Iterator

from int3.errors import Int3MissingEntityError, Int3SatError
from int3.factor import FactorOperation, FactorResult, factor
from int3.gadgets import Gadget, MultiGadget
from int3.immediates import Immediate, IntImmediate
from int3.registers import Registers

from .architecture_emitter import ArchitectureEmitter


class SemanticEmitter(ArchitectureEmitter[Registers]):
    def _gadget_from_factor_result(
        self, dst: Registers, factor_result: FactorResult
    ) -> Gadget:
        factor_gadgets = []
        for factor_clause in factor_result.clauses:
            match factor_clause.operation:
                case FactorOperation.Init:
                    # TODO: It's possible that mov is not possible due to bad byte constraints.
                    # TODO: This could also be something like xor chained with add.
                    gadget = self.literal_mov(dst, factor_clause.operand)
                case FactorOperation.Add:
                    # TODO: Add (and the remaining operations) don't work for 64-bit operands
                    #       in x86_64, which must be first moved to a register to then be
                    #       added.
                    gadget = self.literal_add(dst, factor_clause.operand)
                case FactorOperation.Sub:
                    gadget = self.literal_sub(dst, factor_clause.operand)
                case FactorOperation.Xor:
                    gadget = self.literal_xor(dst, factor_clause.operand)
                case _:
                    raise Int3MissingEntityError(
                        f"Unexpected factor op: {factor_clause.operation}"
                    )

            factor_gadgets.append(gadget)

        return MultiGadget(*factor_gadgets)

    def _find_mov_immediate_width(self, dst: Registers, imm: IntImmediate) -> int:
        """Determine the bit width the imm would take up in a mov operation into dst."""
        # TODO
        1/0

        # Increment the size of our immediate until it occupies the same bit width
        # as the provided imm value. The gradual growth in the size of the assembly
        # represents the "immediate width" of imm.
        # TODO

        return -1

    def mov(self, dst: Registers, src: Registers | IntImmediate):
        self.choose_and_emit(self._mov_iter(dst, src))

    def _mov_iter(
        self, dst: Registers, src: Registers | IntImmediate
    ) -> Iterator[Gadget]:
        # See if naive solution works.
        if (gadget := self.literal_mov(dst, src)).is_okay(self.ctx):
            yield gadget

        # When a bad byte is in the immediate operand, we can try to break apart
        # the operand into multiple operations of the same type.
        if isinstance(src, IntImmediate) and not self.ctx.is_okay_immediate(src):
            # TODO: Determine which operations are forbidden based on the current
            #       context, and apply those constraints in the factor() call below.

            width = self._find_mov_immediate_width(dst=dst, imm=src)
            factor_result = factor(target=src, ctx=self.ctx, width=width)
            yield self._gadget_from_factor_result(dst=dst, factor_result=factor_result)

        # When a bad byte is in the register operand, we can piece together
        # operations on multiple available registers.
        # TODO

        # When a bad byte is in the operation itself, we can attempt to piece
        # together multiple operations in to the equivalent operation.
        # TODO

        # TODO
        yield Gadget("__invalid__")

    def load(self, dst: Registers, src_ptr: Registers, offset: int = 0):
        # See if naive solution works.
        if (gadget := self.literal_load(dst, src_ptr, offset)).is_okay(self.ctx):
            return self.emit(gadget)

        # TODO
        raise Int3SatError("load() unable to find suitable gadget")

    def push(self, value: Registers | Immediate):
        # See if naive solution works.
        if (gadget := self.literal_push(value)).is_okay(self.ctx):
            return self.emit(gadget)

        # TODO
        raise Int3SatError("push() unable to find suitable gadget")

    def pop(self, result: Registers | None = None) -> Registers:
        if result is None:
            raise NotImplementedError(
                "Dynamic register selection not yet implemented"
            )

        # See if naive solution works.
        if (gadget := self.literal_pop(result)).is_okay(self.ctx):
            self.emit(gadget)
            return result

        # TODO
        raise Int3SatError("pop() unable to find suitable gadget")

    def add(self, dst: Registers, operand: Registers | IntImmediate):
        # See if naive solution works.
        if (gadget := self.literal_add(dst, operand)).is_okay(self.ctx):
            return self.emit(gadget)

        # TODO
        raise Int3SatError("add() unable to find suitable gadget")

    def sub(self, dst: Registers, operand: Registers | IntImmediate):
        # See if naive solution works.
        if (gadget := self.literal_sub(dst, operand)).is_okay(self.ctx):
            return gadget

        # TODO
        raise Int3SatError("sub() unable to find suitable gadget")

    def xor(self, dst: Registers, operand: Registers | IntImmediate):
        # See if naive solution works.
        if (gadget := self.literal_xor(dst, operand)).is_okay(self.ctx):
            return gadget

        # TODO
        raise Int3SatError("xor() unable to find suitable gadget")

    def neg(self, dst: Registers):
        # See if naive solution works.
        if (gadget := self.literal_neg(dst)).is_okay(self.ctx):
            return gadget

        # TODO
        raise Int3SatError("neg() unable to find suitable gadget")

    def call(self, target: Registers):
        # See if naive solution works.
        if (gadget := self.literal_call(target)).is_okay(self.ctx):
            return gadget

        # TODO
        raise Int3SatError("call() unable to find suitable gadget")

    def breakpoint(self):
        return self.emit(self.literal_breakpoint())

    # TODO: Shifts?

    def alloc_stack_frame(self, size: IntImmediate):
        # TODO
        raise Int3SatError("alloc_stack_frame() unable to find suitable gadget")

    def label(self, name: str):
        return self.emit(self.literal_label(name))
