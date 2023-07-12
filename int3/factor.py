import itertools
from dataclasses import dataclass
from enum import Enum, auto
from typing import Sequence

from z3 import BitVec, BitVecVal, Extract, Solver, sat

from int3.context import Context
from int3.errors import Int3ArgumentError


class FactorOperation(Enum):
    Init = auto()

    Add = auto()
    Sub = auto()
    Xor = auto()


@dataclass(frozen=True)
class FactorClause:
    operation: FactorOperation
    operand: int


@dataclass(frozen=True)
class FactorResult:
    clauses: tuple[FactorClause, ...]


def factor(
    target: int,
    ctx: Context,
    width: int | None = None,
    max_depth: int = 2,
    allowed_ops: Sequence[FactorOperation] | None = None,
    forbidden_ops: Sequence[FactorOperation] | None = None,
    start: int | None = None,
) -> FactorResult:
    """Emit sets of operations that achieve the target value.

    The following arguments are available:
        target: TODO
        context: TODO
        width: TODO
        max_depth: TODO
        allowed_ops: TODO
        forbidden_ops: TODO
        start: TODO

    The `start` argument may specify an initial start value. When omitted, one
    will be selected by the SAT engine.

    """
    forbidden_ops_iter = tuple() if forbidden_ops is None else tuple(forbidden_ops)

    # Init is implied to always be allowed, since we have to start with some
    # value.
    if FactorOperation.Init in forbidden_ops_iter:
        raise Int3ArgumentError(f"{FactorOperation.Init} cannot be forbidden")

    if allowed_ops is None:
        allowed_ops = (
            FactorOperation.Add,
            FactorOperation.Sub,
            FactorOperation.Xor,
        )

    # Using a list rather than set differences to preserve order.
    allowed_ops = tuple(op for op in allowed_ops if op not in forbidden_ops_iter)

    # Default the width to the passed context.
    if width is None:
        width = ctx.architecture.bit_size

    if (num_target_bits := target.bit_length()) > width:
        raise Int3ArgumentError(
            f"Target would require {num_target_bits} bits to represent, "
            f"but we are using a width of {width}"
        )

    if start is None:
        start_var = BitVec("start", width)
    else:
        start_var = BitVecVal(start, width)

    solver = Solver()

    for depth in range(1, max_depth + 1):
        for op_product in itertools.product(allowed_ops, repeat=depth):
            print(op_product)

    if solver.check() != sat:
        # TODO
        pass
