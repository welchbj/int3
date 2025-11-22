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


@dataclass(frozen=True)
class Aarch64ConstraintProvider(ArchConstraintProvider):
    """AArch64-specific constraint provider.

    AArch64 add/sub immediate instructions encode a 12-bit unsigned immediate
    with an optional 12-bit left shift:

    - imm12: 12-bit immediate value (0-4095)
    - sh: shift bit (0=no shift, 1=LSL #12)

    Instruction format (little-endian bytes for add/sub immediate):

    - Byte 0: Rn[1:0] (bits 7-6) | Rd[4:0] (bits 4-0)
    - Byte 1: imm12[5:0] (bits 7-2) | Rn[4:2] (bits 1-0)
    - Byte 2: sh (bit 6) | imm12[11:6] (bits 5-0)
    - Byte 3: opcode bits (sf, op, S, fixed)

    The immediate bits that can contain bad bytes are:
    - imm12[5:0] in byte 1 (upper 6 bits)
    - imm12[11:6] + sh in byte 2 (lower 7 bits)

    """

    def add_constraints(
        self, solver: Solver, op: FactorOperation, bv: BitVecType
    ) -> None:
        match op:
            case FactorOperation.Add | FactorOperation.Sub:
                self._add_addsub_immediate_constraints(solver, bv)
            case _:
                # For Init, Xor, and other operations, use passthrough behavior.
                # (Xor uses logical immediate encoding which is much more complex)
                self.add_passthrough_constraints(solver, op, bv)

    def _add_addsub_immediate_constraints(self, solver: Solver, bv: BitVecType) -> None:
        """Constrain immediates based on AArch64 add/sub immediate encoding.

        We consider two encoding options:

        - sh=0: imm12 used directly (values 0-4095)
        - sh=1: imm12 << 12 (values 0x1000, 0x2000, ..., 0xFFF000)

        For each option, we check if the resulting instruction bytes are clean.

        Instruction byte layout:

        - Byte 1 bits [7:2] = imm12[5:0]
        - Byte 2 bits [5:0] = imm12[11:6], bit 6 = sh

        Since Rn bits in byte 1 are typically low register numbers and byte 0
        contains Rd/Rn bits (not immediate), we focus on the immediate-containing
        portions of bytes 1 and 2.

        """
        width = cast(int, self.ctx.width)

        # Strategy: Check both shift options and require at least one to work.
        encoding_cases = []

        # Case 1: sh=0, imm12 used directly
        #
        # The value must fit in 12 bits
        # (upper bits must be zero)
        if width > 12:
            sh0_value_fits = Extract(width - 1, 12, bv) == BitVecVal(0, width - 12)
        else:
            # Constrain to an always-true expression.
            sh0_value_fits = BitVecVal(1, 1) == BitVecVal(1, 1)

        # Extract the 12-bit immediate for sh=0 case.
        imm12_sh0 = Extract(11, 0, bv) if width >= 12 else bv

        # Byte 1: bits [7:2] = imm12[5:0], bits [1:0] = Rn[4:2]
        # We check the upper 6 bits combined with worst-case Rn bits
        # Since Rn can be any register (0-31), bits [1:0] can be 0-3
        # We need to ensure that for ANY valid Rn, the byte is clean.
        #
        # Conservative approach: check with Rn bits = 0 (most restrictive
        # for null byte).
        imm12_low = Extract(5, 0, imm12_sh0)
        byte1_sh0 = Concat(imm12_low, BitVecVal(0, 2))

        # Byte 2: bit 6 = sh (=0), bits [5:0] = imm12[11:6]
        imm12_high = Extract(11, 6, imm12_sh0)
        byte2_sh0 = Concat(BitVecVal(0, 2), imm12_high)  # sh=0, plus 1 unused bit

        byte1_sh0_clean = And(
            *[byte1_sh0 != bad_byte for bad_byte in self.ctx.bad_bytes]
        )
        byte2_sh0_clean = And(
            *[byte2_sh0 != bad_byte for bad_byte in self.ctx.bad_bytes]
        )

        encoding_cases.append(And(sh0_value_fits, byte1_sh0_clean, byte2_sh0_clean))

        # Case 2: sh=1, imm12 << 12
        #
        # The value must be a multiple of 0x1000 with imm12 in upper bits
        # and lower 12 bits must be zero
        lower_12_zero = Extract(11, 0, bv) == BitVecVal(0, 12)

        # Extract imm12 from bits [23:12] for sh=1 case.
        if width >= 24:
            imm12_sh1 = Extract(23, 12, bv)
            # Upper bits above 24 must be zero
            sh1_upper_zero = Extract(width - 1, 24, bv) == BitVecVal(0, width - 24)
            sh1_value_fits = And(lower_12_zero, sh1_upper_zero)
        elif width > 12:
            imm12_sh1 = Extract(width - 1, 12, bv)
            # Pad to 12 bits
            imm12_sh1 = Concat(BitVecVal(0, 24 - width), imm12_sh1)
            sh1_value_fits = lower_12_zero
        else:
            # Width <= 12, sh=1 case not applicable (would need at least 13 bits)
            imm12_sh1 = BitVecVal(0, 12)
            sh1_value_fits = BitVecVal(0, 1) == BitVecVal(1, 1)  # Always false

        # Byte 1 with sh=1: same structure, imm12[5:0] from shifted position
        imm12_sh1_low = Extract(5, 0, imm12_sh1)
        byte1_sh1 = Concat(imm12_sh1_low, BitVecVal(0, 2))

        # Byte 2 with sh=1: bit 6 = sh (=1), bits [5:0] = imm12[11:6]
        imm12_sh1_high = Extract(11, 6, imm12_sh1)
        byte2_sh1 = Concat(BitVecVal(1, 2), imm12_sh1_high)  # sh=1

        byte1_sh1_clean = And(
            *[byte1_sh1 != bad_byte for bad_byte in self.ctx.bad_bytes]
        )
        byte2_sh1_clean = And(
            *[byte2_sh1 != bad_byte for bad_byte in self.ctx.bad_bytes]
        )

        encoding_cases.append(And(sh1_value_fits, byte1_sh1_clean, byte2_sh1_clean))

        # At least one encoding must produce valid (clean) bytes
        solver.add(Or(*encoding_cases))


def constraint_provider_for(ctx: FactorContext) -> ArchConstraintProvider:
    """Resolve the appropriate constraint provider for an architecture.

    If no architecture-specific providers are applicable, a default
    pass-through provider will be returned.

    """
    provider_cls: type[ArchConstraintProvider]

    match ctx.arch:
        case Architectures.Arm.value:
            provider_cls = ArmConstraintProvider
        case Architectures.Aarch64.value:
            provider_cls = Aarch64ConstraintProvider
        case _:
            provider_cls = PassThroughConstraintProvider

    return provider_cls(ctx)
