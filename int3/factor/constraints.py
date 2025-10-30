from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import cast

from z3 import (
    And,
    BitVecNumRef,
    BitVecRef,
    BitVecVal,
    Concat,
    Extract,
    LShR,
    Or,
    Solver,
)

from int3.architecture import Architectures

from .context import FactorContext, ImmediateMutationContext
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

    def add_passthrough_constraints(
        self, solver: Solver, op: FactorOperation, bv: BitVecType
    ) -> None:
        """Add constraints based on direct bad byte values."""
        width = cast(int, self.ctx.width)

        for bad_byte in self.ctx.bad_bytes:
            for i in range(0, width, self.ctx.byte_width):
                solver.add(Extract(i + self.ctx.byte_width - 1, i, bv) != bad_byte)

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
        self.add_passthrough_constraints(solver, op, bv)


@dataclass(frozen=True)
class ArmConstraintProvider(ArchConstraintProvider):
    """ARM-specific constraint provider.

    ARM has multiple immediate encoding schemes:

    - movw/movt: 16-bit immediates in non-contiguous fields
    - Modified immediate constants: 12-bit encoding (8-bit value + 4-bit rotation)
      used by data processing instructions (add, sub, eor, etc.)

    This provider takes a best guess approach at adding the appropriate constraints
    for the instruction(s) likely to correspond to the given factor operations.

    """

    def add_constraints(
        self, solver: Solver, op: FactorOperation, bv: BitVecType
    ) -> None:
        match op:
            case FactorOperation.Init:
                # Init operations generate mov/movw instructions to load immediates.
                # These use the movw encoding for 16-bit values.
                self._add_movw_constraints(solver, bv)
            case FactorOperation.Add | FactorOperation.Sub | FactorOperation.Xor:
                # These operations first attempt direct immediate encoding using
                # modified immediate constants (8-bit value + 4-bit rotation).
                # Apply constraints for this encoding scheme.
                self._add_modified_immediate_constraints(solver, bv)
            case _:
                # For any other operations, use passthrough behavior
                self.add_passthrough_constraints(solver, op, bv)

    def _add_movw_constraints(self, solver: Solver, bv: BitVecType) -> None:
        """Constrain immediates based on ARM movw encoding.

        movw instruction (little-endian bytes):

        - Byte 0: imm12[7:0]
        - Byte 1: Rd[3:0] (lower) | imm12[11:8] (upper)
        - Byte 2: fixed[3:0] (lower) | imm4[3:0] (upper)
        - Byte 3: fixed (0xE3)

        We only constrain the bytes containing immediate bits.

        """
        imm12 = Extract(11, 0, bv)
        imm4 = Extract(15, 12, bv)

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

    def _add_modified_immediate_constraints(
        self, solver: Solver, bv: BitVecType
    ) -> None:
        """Constrain immediates based on ARM modified immediate constant encoding.

        Modified immediate constants are used in data processing instructions (add,
        sub, eor, etc.) and encode a 12-bit field as:

        - Bits [11:8]: 4-bit rotation value (actual rotation = value * 2)
        - Bits [7:0]: 8-bit immediate value

        The 32-bit immediate is formed by ROR(imm8, rotation * 2), where ROR is
        rotate right and rotation ranges from 0-15 (giving rotations of 0, 2, 4, 6,
        ..., 30).

        Not all 32-bit values can be represented - only those that can be formed
        by rotating an 8-bit value by an even number of bit positions.

        Instruction format (little-endian bytes):

        - Byte 0: imm8[7:0] - the 8-bit immediate before rotation
        - Byte 1: Rd[3:0] (lower nibble) | rotation[3:0] (upper nibble)
        - Byte 2-3: Other instruction bits

        We constrain both the value (must be encodable as modified immediate) and
        the encoded bytes (must not contain bad bytes).

        See:

            https://alisdair.mcdiarmid.org/arm-immediate-value-encoding/

        """
        # Strategy: Check all 16 possible rotations (0-15) and create constraints
        # that imply at least one rotation produces the target value AND has clean bytes.

        rotation_cases = []

        for rot_val in range(0x10):
            rotation_amount = rot_val * 2

            # For this rotation, compute what imm8 would need to be.
            # If bv == ROR(imm8, rotation_amount), then imm8 == ROL(bv, rotation_amount)
            # ROL(x, n) = (x << n) | (x >> (32 - n))

            if rotation_amount == 0:
                # No rotation needed.
                imm8_for_this_rotation = Extract(7, 0, bv)
                # The value must fit in 8 bits (upper 24 bits must be zero).
                value_constraint = Extract(31, 8, bv) == BitVecVal(0, 24)
            else:
                # Rotate left to recover the original 8-bit value.
                rot_left = rotation_amount
                rot_right = 32 - rotation_amount

                # ROL(var, rot_left) = (var << rot_left) | (var >> rot_right)
                rotated_left = (bv << rot_left) | LShR(bv, rot_right)
                imm8_for_this_rotation = Extract(7, 0, rotated_left)

                # The value must be such that rotating imm8 gives us bv.
                # This means the upper 24 bits of rotated_left must be zero.
                value_constraint = Extract(31, 8, rotated_left) == BitVecVal(0, 24)

            # Byte 0: imm8
            byte0_clean = And(
                *[imm8_for_this_rotation != bad_byte for bad_byte in self.ctx.bad_bytes]
            )

            # Byte 1 (bits 8-15 of instruction): Rd[3:0] (upper nibble, bits 12-15) | rotation[3:0] (lower nibble, bits 8-11)
            # In Concat, first arg goes to high bits: Concat(Rd, rotation)
            # We assume Rd bits can be any register, so we check with Rd=0
            rot_bits = BitVecVal(rot_val, 4)
            byte1 = Concat(BitVecVal(0, 4), rot_bits)
            byte1_clean = And(*[byte1 != bad_byte for bad_byte in self.ctx.bad_bytes])

            # This rotation works if: value fits AND bytes are clean.
            rotation_cases.append(And(value_constraint, byte0_clean, byte1_clean))

        # At least one rotation must produce a valid encoding.
        solver.add(Or(*rotation_cases))


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
