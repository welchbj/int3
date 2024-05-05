from dataclasses import dataclass
from typing import Sequence

from int3.architectures import ArchitectureMeta

from .factor_operation import FactorOperation


@dataclass(frozen=True)
class FactorContext:
    arch_meta: ArchitectureMeta

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
