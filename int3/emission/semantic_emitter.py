from __future__ import annotations

import logging
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Generic, Iterator

from int3.architectures import InstructionWidth
from int3.errors import (
    Int3ArgumentError,
    Int3LockedRegisterError,
    Int3MissingEntityError,
    Int3SatError,
)
from int3.factor import FactorOperation, FactorResult, factor
from int3.gadgets import Gadget, MultiGadget
from int3.immediates import BytesImmediate, Immediate, IntImmediate
from int3.registers import Registers

from .architecture_emitter import ArchitectureEmitter


@dataclass(frozen=True)
class BoundRegisterScope(Generic[Registers]):
    regs: set[Registers] = field(default_factory=set)


@dataclass
class SemanticEmitter(ArchitectureEmitter[Registers]):
    bound_register_scopes: list[BoundRegisterScope[Registers]] = field(
        init=False, default_factory=list
    )

    @property
    def free_gp_registers(self) -> tuple[Registers, ...]:
        return tuple(
            reg
            for reg in self.ctx.architecture.gp_regs
            if reg not in self.locked_gp_registers
        )

    @property
    def locked_gp_registers(self) -> set[Registers]:
        return set().union(*[scope.regs for scope in self.bound_register_scopes])

    @contextmanager
    def locked(self, *regs: Registers) -> Iterator[SemanticEmitter]:
        # Identify duplicates in regs.
        regs_set = set(regs)
        if len(regs_set) != len(regs):
            raise Int3ArgumentError(f"Register set {regs} contains duplicates")

        # Identify any registers-to-lock that aren't actually free.
        locked_regs = regs_set & self.locked_gp_registers
        if locked_regs:
            locked_regs_str = ", ".join(sorted(locked_regs))
            raise Int3LockedRegisterError(
                f"Registers are already locked: {locked_regs_str}"
            )

        # Of note, the below approach is not thread-safe.

        self.bound_register_scopes.append(BoundRegisterScope(regs_set))
        yield self
        self.bound_register_scopes.pop()

    def _gadget_from_factor_result(
        self, dst: Registers, factor_result: FactorResult
    ) -> Gadget:
        factor_gadgets = []
        for factor_clause in factor_result.clauses:
            if factor_clause.operation == FactorOperation.Init:
                # TODO: It's possible that mov is not possible due to bad byte
                #       constraints.
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
        end = len(packed_instruction)
        null_run_right = sum(
            1 for i in range(imm_idx + 1, end) if packed_instruction[i] == 0
        )

        # Left search.
        null_run_left = sum(
            1 for i in range(imm_idx - 1, -1, -1) if packed_instruction[i] == 0
        )

        num_bytes = len(packed_imm) + max(null_run_left, null_run_right)
        return num_bytes * self.ctx.byte_width

    def _find_literal_mov_dst(self, src: Registers | IntImmediate) -> Registers:
        """Find a general-purpose destination register for a move."""
        for gp_register in self.free_gp_registers:
            if self.literal_mov(dst=gp_register, src=src).is_okay(ctx=self.ctx):
                return gp_register

        raise Int3SatError("Unable to find free gp register that meets constraints")

    def mov(self, dst: Registers, src: Registers | Immediate):
        self.choose_and_emit(self._mov_iter(dst, src))

    def _mov_iter(self, dst: Registers, src: Registers | Immediate) -> Iterator[Gadget]:
        if isinstance(src, BytesImmediate):
            raise NotImplementedError("Bytes immediate for mov() not yet implemented")

        # See if naive solution works.
        if (gadget := self.literal_mov(dst, src)).is_okay(self.ctx):
            yield gadget

        # See if a simple XOR works.
        if src == 0:
            yield self.literal_xor(dst=dst, operand=dst)

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

            try:
                yield self._gadget_from_factor_result(
                    dst=dst, factor_result=factor_result
                )
            except Int3SatError:
                logging.debug(
                    f"Unable convert factor result [{factor_result}] into usable "
                    "gadgets"
                )

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

    def memcpy(
        self, dst: Registers, src: Registers | BytesImmediate, n: int | None = None
    ):
        # TODO
        raise Int3SatError("memcpy() unable to find suitable gadget")

    def alloc_stack_frame(self, size: IntImmediate):
        # TODO
        raise Int3SatError("alloc_stack_frame() unable to find suitable gadget")

    def label(self, name: str):
        return self.emit(self.literal_label(name))
