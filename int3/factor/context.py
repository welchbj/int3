from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Sequence

from int3.architecture import Architecture, RegisterDef
from int3.errors import Int3MissingEntityError

from .factor_operation import FactorOperation

if TYPE_CHECKING:
    from int3.codegen import Instruction


@dataclass(frozen=True)
class ImmediateMutationContext:
    """Context for a mutation of an immediate value."""

    arch: Architecture
    bad_bytes: bytes
    imm: int
    dest: RegisterDef
    scratch_regs: tuple[RegisterDef, ...]

    scratch_regs_set: frozenset[RegisterDef] = field(init=False)
    byte_width: int = field(init=False, default=8)

    def __post_init__(self) -> None:
        object.__setattr__(self, "scratch_regs_set", frozenset(self.scratch_regs))

    def with_locked_reg(self, reg: RegisterDef) -> ImmediateMutationContext:
        if reg not in self.scratch_regs_set:
            raise Int3MissingEntityError(
                f"Cannot lock reg {reg} that is not in this context's scratch regs"
            )

        modified_scratch_regs = tuple(
            scratch_reg for scratch_reg in self.scratch_regs if scratch_reg != reg
        )
        return replace(self, scratch_regs=modified_scratch_regs)


@dataclass(frozen=True)
class FactorContext:
    """Context for a factoring solve."""

    arch: Architecture

    # The target value.
    target: int

    # The bytes that should be avoided in generated factor operands.
    bad_bytes: bytes = b""

    # The maximum amount of nested operations to permit.
    max_depth: int = 3

    # The number of bits to assume are in a byte.
    byte_width: int = 8

    # Whether to allow for overflows or underflows during bitwise operations.
    allow_overflow: bool = True

    # The bit width of values to assume.
    width: int | None = None

    # The operations (add, xor, etc.) that may be used by the engine.
    allowed_ops: Sequence[FactorOperation] | None = None

    # The operations (add, xor, etc.) that cannot be used by the engine.
    forbidden_ops: Sequence[FactorOperation] | None = None

    # The initial value to work from. When omitted, the engine will select
    # one based on the existing constraints.
    start: int | None = None

    # Additional context related to the assembly instruction that originated
    # this factor requirement. This is mainly useful for understanding the
    # instruction being mutated, as this informs what instruction-specific
    # immediate encoding constraints should be applied.
    imm_mut_ctx: ImmediateMutationContext | None = None
