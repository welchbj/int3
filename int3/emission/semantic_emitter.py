from dataclasses import dataclass, field
from typing import Iterator, get_args

from int3.architectures import InstructionWidth
from int3.errors import Int3MissingEntityError, Int3SatError
from int3.factor import FactorOperation, FactorResult, factor
from int3.gadgets import Gadget, MultiGadget
from int3.immediates import Immediate, IntImmediate
from int3.registers import Registers

from .architecture_emitter import ArchitectureEmitter


@dataclass
class BoundRegisterScope:
    # TODO
    pass


@dataclass
class SemanticEmitter(ArchitectureEmitter[Registers]):
    # TODO: Implement this properly with free_gp_registers.
    bound_register_scopes: list[BoundRegisterScope] = field(init=False, default_factory=list)

    gp_registers: tuple[Registers, ...] = field(init=False, default_factory=tuple)

    def __post_init__(self):
        # TODO: This currently returns *all* registers for an architecture.
        #       Need to find a good way of reducing to just the gp registers.
        #
        # TODO: Should potentially do some searching logic to find the literal
        #       generic type, to not be reliant upon inheritance order.
        self.gp_registers = get_args(get_args(self.__orig_bases__[1])[0])

    @property
    def free_gp_registers(self) -> tuple[Registers, ...]:
        # TODO: Find the difference with the currently-bound set of registers.
        return self.gp_registers

    def _gadget_from_factor_result(
        self, dst: Registers, factor_result: FactorResult
    ) -> Gadget:
        factor_gadgets = []
        for factor_clause in factor_result.clauses:
            if factor_clause.operation == FactorOperation.Init:
                # TODO: It's possible that mov is not possible due to bad byte constraints.
                # TODO: This could also be something like xor chained with add.
                factor_gadgets.append(self.literal_mov(dst, factor_clause.operand))
                continue

            imm = factor_clause.operand
            intermediate_dst = self._find_literal_mov_dst(src=imm)
            mov_gadget = self.literal_mov(dst=intermediate_dst, src=imm)

            match factor_clause.operation:
                case FactorOperation.Add:
                    arithmetic_gadget = self.literal_add(dst, intermediate_dst)
                case FactorOperation.Sub:
                    arithmetic_gadget = self.literal_sub(dst, intermediate_dst)
                case FactorOperation.Xor:
                    arithmetic_gadget = self.literal_xor(dst, intermediate_dst)
                case _:
                    raise Int3MissingEntityError(
                        f"Unexpected factor op: {factor_clause.operation}"
                    )

            factor_gadgets.append(MultiGadget(mov_gadget, arithmetic_gadget))

        return MultiGadget(*factor_gadgets)

    def _find_mov_immediate_width(self, dst: Registers, imm: IntImmediate) -> int:
        """Determine the bit width the imm would take up in a mov operation into dst."""
        arch = self.ctx.architecture

        packed_imm = arch.pack(imm).strip(b"\x00")
        if not packed_imm:
            packed_imm = b"\x00"

        # Find runs of null bytes in either direction from the packed immediate in
        # the assembled instruction.
        packed_instruction = self.literal_mov(dst=dst, src=imm).assembled(ctx=self.ctx)
        imm_idx = packed_instruction.rfind(packed_imm)

        # Right search.
        null_run_right = sum(
            1 for i in range(imm_idx + 1, len(packed_instruction))
            if packed_instruction[i] == 0
        )

        # Left search.
        null_run_left = sum(
            1 for i in range(imm_idx - 1, -1, -1)
            if packed_instruction[i] == 0
        )

        return self.ctx.byte_width * (len(packed_imm) + max(null_run_left, null_run_right))

    def _find_literal_mov_dst(self, src: Registers | IntImmediate) -> Registers:
        """Find a general-purpose destination register for a move."""
        for gp_register in self.free_gp_registers:
            if self.literal_mov(dst=gp_register, src=src).is_okay(ctx=self.ctx):
                return gp_register

        raise Int3SatError("Unable to find free gp register that meets constraints")

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

            if self.ctx.architecture.instruction_width == InstructionWidth.Fixed:
                # TODO: This is likely not correct (e.g., arm encoded immediates have
                #       a shorter length than the max register width).
                width = self.ctx.architecture.bit_size
            else:
                width = self._find_mov_immediate_width(dst=dst, imm=src)

            factor_result = factor(target=src, ctx=self.ctx, width=width)
            yield self._gadget_from_factor_result(dst=dst, factor_result=factor_result)

        # When a bad byte is in the register operand, we can piece together
        # operations on multiple available registers.
        # TODO

        # When a bad byte is in the operation itself, we can attempt to piece
        # together multiple operations in to the equivalent operation.
        # TODO
        # TODO: Bad byte "\xc1" is a good test here.

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
            raise NotImplementedError("Dynamic register selection not yet implemented")

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
