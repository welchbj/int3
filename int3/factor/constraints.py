from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, cast

from z3 import BitVecNumRef, BitVecRef, BitVecVal, Concat, Extract, Solver

from int3.architecture import Architectures

from .context import FactorContext
from .factor_operation import FactorOperation

type BitVecType = BitVecRef | BitVecNumRef


@dataclass(frozen=True)
class ArchConstraintProvider(ABC):
    """Base class for architecture-specific constraint providers."""

    ctx: FactorContext

    @abstractmethod
    def add_constraints(
        self, solver: Solver, op: FactorOperation, bv: BitVecType
    ) -> None:
        """Add architecture-aware z3 constraints to avoid bad bytes."""

    def constrain_byte(self, solver: Solver, bv: BitVecType) -> None:
        """Utility to add constraints that a byte expression != any bad byte."""
        for bad_byte in self.ctx.bad_bytes:
            solver.add(bv != bad_byte)


@dataclass(frozen=True)
class PassThroughConstraintProvider(ArchConstraintProvider):
    """No-op constraint provider for architectures with direct immediate encoding."""

    def add_constraints(
        self, solver: Solver, op: FactorOperation, bv: BitVecType
    ) -> None:
        width = cast(int, self.ctx.width)

        for bad_byte in self.ctx.bad_bytes:
            for i in range(0, width, self.ctx.byte_width):
                solver.add(Extract(i + self.ctx.byte_width - 1, i, bv) != bad_byte)


@dataclass(frozen=True)
class ArmConstraintProvider(ArchConstraintProvider):
    """ARM-specific constraint provider.

    ARM movw encodes 16-bit immediates across non-contiguous bit fields:
    - Bits [19:16]: imm4 (immediate[15:12])
    - Bits [11:0]:  imm12 (immediate[11:0])

    The encoded immediate bytes appear at specific positions in the instruction.

    """

    def add_constraints(self, solver: Solver, op: FactorOperation, var: Any) -> None:
        # TODO: We need to branch based on the actual instruction being used here.
        # TODO: In that event, how do we fall back to our pass-through behavior?

        # ARM uses movw for Init, and falls back to movw for Add/Sub/Xor when
        # immediates can't fit in the "modified immediate" encoding
        self._add_movw_constraints(solver, var)

    def _add_movw_constraints(self, solver: Solver, var: Any) -> None:
        """Constrain immediates based on ARM movw encoding.

        movw instruction (little-endian bytes):
        Byte 0: imm12[7:0]
        Byte 1: Rd[3:0] (lower) | imm12[11:8] (upper)
        Byte 2: fixed[3:0] (lower) | imm4[3:0] (upper)
        Byte 3: fixed (0xE3)

        We only constrain the bytes containing immediate bits.
        """
        if self.ctx.width > 32:
            # TODO: Raise error?
            return

        imm12 = Extract(11, 0, var)
        imm4 = Extract(15, 12, var)

        # Byte 0: imm12[7:0]
        byte0 = Extract(7, 0, imm12)
        self.constrain_byte(solver, byte0)

        # Byte 1: bits [15:8] = Rd[3:0] (upper nibble) | imm12[11:8] (lower nibble)
        # In Concat, first arg is high bits: Concat(Rd, imm12_high) = (Rd << 4) | imm12_high
        byte1_imm = Extract(11, 8, imm12)
        byte1 = Concat(BitVecVal(0, 4), byte1_imm)
        self.constrain_byte(solver, byte1)

        # Byte 2: bits [23:16] = fixed[3:0] (upper nibble) | imm4[3:0] (lower nibble)
        # Concat(fixed, imm4) = (fixed << 4) | imm4
        byte2 = Concat(BitVecVal(0, 4), imm4)
        self.constrain_byte(solver, byte2)


def constraint_provider_for(ctx: FactorContext) -> ArchConstraintProvider:
    """Resolve the appropriate constraint provider for an architecture.

    If no architecture-specific providers are applicable, a default
    pass-through provider will be returned.

    """
    provider_cls: type[ArchConstraintProvider]

    if ctx.insn_ctx is None:
        # If we have no passed arch/instruction-specific context, we use the default
        # passthrough behavior.
        provider_cls = PassThroughConstraintProvider
    else:
        match ctx.arch:
            case Architectures.Arm.value:
                provider_cls = ArmConstraintProvider
            case _:
                provider_cls = PassThroughConstraintProvider

    return provider_cls(ctx)
