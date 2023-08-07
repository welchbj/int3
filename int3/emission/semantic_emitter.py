from __future__ import annotations

import functools
import itertools
import logging
from contextlib import contextmanager
from dataclasses import dataclass, field
from io import BytesIO
from typing import Any, Generic, Iterable, Iterator, Protocol

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


class UnboundGadgetFunc(Protocol):
    def __call__(self, reg: Any) -> Iterator[Gadget]:
        ...


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
        self, dst: Registers, intermediate_dst: Registers, factor_result: FactorResult
    ) -> Gadget:
        factor_gadgets = []
        for factor_clause in factor_result.clauses:
            if factor_clause.operation == FactorOperation.Init:
                factor_gadgets.append(self.literal_mov(dst, factor_clause.operand))
                continue

            imm = factor_clause.operand
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
        return num_bytes * self.ctx.architecture.BITS_IN_A_BYTE

    def _find_literal_mov_dst(self, src: Registers | IntImmediate) -> Registers:
        """Find a general-purpose destination register for a move."""
        for gp_register in self.free_gp_registers:
            if self.literal_mov(dst=gp_register, src=src).is_okay(ctx=self.ctx):
                return gp_register

        raise Int3SatError("Unable to find free gp register that meets constraints")

    def _find_free_gp_reg_for(
        self, *gadget_funcs: UnboundGadgetFunc
    ) -> Iterator[Registers]:
        """Find a stream of free gp registers that can be used in all provided funcs."""

        def _has_at_least_one_okay_gadget(gadgets: Iterable[Gadget]) -> bool:
            return any(gadget.is_okay(self.ctx) for gadget in gadgets)

        for reg in self.free_gp_registers:
            if all(
                _has_at_least_one_okay_gadget(gadget_func(reg))
                for gadget_func in gadget_funcs
            ):
                yield reg

    def mov(self, dst: Registers, src: Registers | IntImmediate):
        self.choose_and_emit(self._mov_iter(dst, src))

    def _mov_iter(
        self, dst: Registers, src: Registers | IntImmediate
    ) -> Iterator[Gadget]:
        arch = self.ctx.architecture

        # See if naive solution works.
        if (gadget := self.literal_mov(dst, src)).is_okay(self.ctx):
            yield gadget

        # See if a simple XOR works.
        if src == 0:
            yield self.literal_xor(dst=dst, operand=dst)

        # When a bad byte is in the immediate operand, we can try to break apart
        # the operand into multiple operations of the same type.
        if isinstance(src, IntImmediate) and not self.ctx.is_okay_int_immediate(src):
            # Determine which operations are forbidden based on the current
            # context, and apply those constraints in the factor() call below.

            dummy_operand = self.ctx.make_okay_int_immediate()

            # We will require a transitory register for the arthmetic operations;
            # we determine that register here to use in our identification of which
            # factor operations we have available.
            with self.locked(dst):
                intermediate_dst = self._find_literal_mov_dst(src=dummy_operand)

            # Test if addition is permissable.
            have_add = self.literal_add(dst, intermediate_dst).is_okay(self.ctx)

            # Test if substraction is permissable.
            have_sub = self.literal_sub(dst, intermediate_dst).is_okay(self.ctx)

            # Test if XOR is permissable.
            have_xor = self.literal_xor(dst, intermediate_dst).is_okay(self.ctx)

            if arch.instruction_width == InstructionWidth.Fixed:
                # TODO: This is likely not correct (e.g., arm encoded immediates have
                #       a shorter length than the max register width).
                width = arch.bit_size
            else:
                width = self._find_mov_immediate_width(dst=dst, imm=src)

            allow_overflow = width == arch.bit_size

            allowed_ops: list[FactorOperation] = []
            if have_add:
                allowed_ops.append(FactorOperation.Add)
            if have_sub:
                allowed_ops.append(FactorOperation.Sub)
            if have_xor:
                allowed_ops.append(FactorOperation.Xor)

            factor_result = factor(
                target=src, ctx=self.ctx, width=width, allow_overflow=allow_overflow
            )

            try:
                yield self._gadget_from_factor_result(
                    dst=dst, intermediate_dst=intermediate_dst, factor_result=factor_result
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

    def store(self, dst: Registers, src: Registers | Immediate):
        self.choose_and_emit(
            self._store_iter(
                dst,
                src,
            )
        )

    def _store_iter(
        self, dst: Registers, src: Registers | Immediate
    ) -> Iterator[Gadget]:
        # See if naive solution works.
        if not isinstance(src, BytesImmediate) and (
            gadget := self.literal_store(dst, src)
        ).is_okay(self.ctx):
            yield gadget

        # TODO

    def load(self, dst: Registers, src_ptr: Registers, offset: int = 0):
        # See if naive solution works.
        if (gadget := self.literal_load(dst, src_ptr, offset)).is_okay(self.ctx):
            return self.emit(gadget)

        # TODO
        raise Int3SatError("load() unable to find suitable gadget")

    def push(self, value: Registers | Immediate):
        self.choose_and_emit(self._push_iter(value))

    def _push_iter(self, value: Registers | Immediate) -> Iterator[Gadget]:
        if not self.ctx.usable_stack:
            raise Int3SatError("Current context does not allow for stack use")

        # Separate code path for handling bytes immediates.
        if isinstance(value, BytesImmediate):
            yield from self._push_bytes_imm_iter(value)
            return

        # We are now dealing with only register or int immediate operands.

        # See if naive solution works.
        if (gadget := self.literal_push(value)).is_okay(self.ctx):
            yield gadget

        # TODO: Other approaches.

    def _push_bytes_imm_iter(self, value: BytesImmediate) -> Iterator[Gadget]:
        arch = self.ctx.architecture

        util_reg = self.choose(
            self._find_free_gp_reg_for(functools.partial(self._push_iter))
        )

        value_f = BytesIO(value)
        reader = functools.partial(value_f.read, arch.byte_size)

        int_imm_list = [
            arch.unpack(arch.pad(int_imm_bytes)) for int_imm_bytes in iter(reader, b"")
        ]

        gadgets = []
        for int_imm in reversed(int_imm_list):
            gadgets.append(
                MultiGadget(
                    self.choose(self._mov_iter(dst=util_reg, src=int_imm)),
                    self.choose(self._push_iter(value=util_reg)),
                )
            )

        yield MultiGadget(*gadgets)

    def push_into(self, buf: BytesImmediate, dst: Registers | None = None) -> Registers:
        sp = self.ctx.architecture.sp_reg

        if dst is None:
            if not self.free_gp_registers:
                raise Int3LockedRegisterError(
                    "No remaining free general purpose registers"
                )

            dst = self._find_literal_mov_dst(src=sp)

        gadget_choices = [
            MultiGadget(push_gadget, mov_gadget)
            for push_gadget, mov_gadget in itertools.product(
                self._push_iter(buf), self._mov_iter(dst, sp)
            )
        ]

        self.choose_and_emit(gadget_choices)
        return dst

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
