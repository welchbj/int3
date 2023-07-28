from typing import Iterator

from int3.errors import Int3MissingEntityError
from int3.factor import FactorOperation, FactorResult, factor
from int3.gadgets import Gadget, MultiGadget
from int3.registers import Immediate, IntImmediate, Registers

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

    def mov(self, dst: Registers, src: Registers | IntImmediate) -> Gadget:
        return self.choose(self._mov_iter(dst, src))

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

            factor_result = factor(target=src, ctx=self.ctx)
            yield self._gadget_from_factor_result(dst=dst, factor_result=factor_result)

        # When a bad byte is in the register operand, we can piece together
        # operations on multiple available registers.
        # TODO

        # When a bad byte is in the operation itself, we can attempt to piece
        # together multiple operations in to the equivalent operation.
        # TODO

        # TODO
        yield Gadget("__invalid__")

    def load(self, dst: Registers, src_ptr: Registers, offset: int = 0) -> Gadget:
        # See if naive solution works.
        if (gadget := self.literal_load(dst, src_ptr, offset)).is_okay(self.ctx):
            return gadget

        # TODO
        return Gadget("__invalid__")

    def push(self, value: Registers | Immediate) -> Gadget:
        # See if naive solution works.
        if (gadget := self.literal_push(value)).is_okay(self.ctx):
            return gadget

        # TODO
        return Gadget("__invalid__")

    def pop(self, result: Registers | None = None) -> Gadget:
        # See if naive solution works.
        if (gadget := self.literal_pop(result)).is_okay(self.ctx):
            return gadget

        # TODO
        return Gadget("__invalid__")

    def add(self, dst: Registers, operand: Registers | IntImmediate) -> Gadget:
        # See if naive solution works.
        if (gadget := self.literal_add(dst, operand)).is_okay(self.ctx):
            return gadget

        # TODO
        return Gadget("__invalid__")

    def sub(self, dst: Registers, operand: Registers | IntImmediate) -> Gadget:
        # See if naive solution works.
        if (gadget := self.literal_sub(dst, operand)).is_okay(self.ctx):
            return gadget

        # TODO
        return Gadget("__invalid__")

    def xor(self, dst: Registers, operand: Registers | IntImmediate) -> Gadget:
        # See if naive solution works.
        if (gadget := self.literal_xor(dst, operand)).is_okay(self.ctx):
            return gadget

        # TODO
        return Gadget("__invalid__")

    def neg(self, dst: Registers) -> Gadget:
        # See if naive solution works.
        if (gadget := self.literal_neg(dst)).is_okay(self.ctx):
            return gadget

        # TODO
        return Gadget("__invalid__")

    def call(self, target: Registers) -> Gadget:
        # See if naive solution works.
        if (gadget := self.literal_call(target)).is_okay(self.ctx):
            return gadget

        # TODO
        return Gadget("__invalid__")

    def breakpoint(self) -> Gadget:
        return self.literal_breakpoint()

    # TODO: Shifts?

    def alloc_stack_frame(self, size: IntImmediate) -> Gadget:
        # TODO
        return Gadget("__invalid__")

    def label(self, name: str) -> Gadget:
        return self.literal_label(name)
