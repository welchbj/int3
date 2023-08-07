import itertools
from dataclasses import dataclass
from enum import Enum, auto
from typing import Any, Sequence

from z3 import (
    BitVec,
    BitVecVal,
    BVAddNoOverflow,
    BVSubNoOverflow,
    BVSubNoUnderflow,
    Extract,
    Solver,
    sat,
)

from int3.context import Context
from int3.errors import Int3ArgumentError, Int3MissingEntityError, Int3SatError


class FactorOperation(Enum):
    Init = auto()

    Add = auto()
    Sub = auto()
    Xor = auto()


@dataclass(frozen=True)
class FactorClause:
    operation: FactorOperation
    operand: int

    def __str__(self) -> str:
        s = ""

        match self.operation:
            case FactorOperation.Init:
                pass
            case FactorOperation.Add:
                s += "+ "
            case FactorOperation.Sub:
                s += "- "
            case FactorOperation.Xor:
                s += "^ "
            case _:
                raise Int3MissingEntityError(f"Unexpected factor op: {self.operation}")

        s += hex(self.operand)
        return s


@dataclass(frozen=True)
class FactorResult:
    clauses: tuple[FactorClause, ...]

    def __str__(self) -> str:
        return " ".join(str(c) for c in self.clauses)


def factor(
    target: int,
    ctx: Context,
    allow_overflow: bool = True,
    width: int | None = None,
    max_depth: int = 2,
    allowed_ops: Sequence[FactorOperation] | None = None,
    forbidden_ops: Sequence[FactorOperation] | None = None,
    start: int | None = None,
) -> FactorResult:
    """Emit sets of operations that achieve the target value.

    The following arguments are available:
        target: TODO
        ctx: TODO
        allow_overflow: TODO
        width: TODO
        max_depth: TODO
        allowed_ops: TODO
        forbidden_ops: TODO
        start: TODO

    The `start` argument may specify an initial start value. When omitted, one
    will be selected by the SAT engine.

    """
    if max_depth < 1:
        raise Int3ArgumentError(
            f"max_depth must be a positive int ({max_depth} is not)"
        )

    # Check if a bad byte was provided in the start value.
    if start is not None and not ctx.is_okay_int_immediate(start, width=width):
        raise Int3ArgumentError(
            f"Specified start value {hex(start)} contains at least one bad byte"
        )

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

    for depth in range(1, max_depth + 1):
        for op_product in itertools.product(allowed_ops, repeat=depth):
            solver = Solver()

            if start is None:
                start_with_bvv = False
                start_bv = BitVec("start", width)
            else:
                start_with_bvv = True
                start_bv = BitVecVal(start, width)

            var_list = [start_bv]
            var_list.extend(BitVec(f"s{i}", width) for i in range(depth))

            bv_list = var_list[1:] if start_with_bvv else var_list
            for bvv in bv_list:
                _add_bad_byte_constraints(solver, bvv, ctx, width)

            solver_clause = var_list[0]

            for bvv, op in zip(var_list[1:], op_product):
                match op:
                    case FactorOperation.Add:
                        if not allow_overflow:
                            solver.add(
                                BVAddNoOverflow(solver_clause, bvv, signed=False)
                            )

                        solver_clause += bvv
                    case FactorOperation.Sub:
                        if not allow_overflow:
                            solver.add(BVSubNoOverflow(solver_clause, bvv))
                            solver.add(
                                BVSubNoUnderflow(solver_clause, bvv, signed=False)
                            )

                        solver_clause -= bvv
                    case FactorOperation.Xor:
                        solver_clause ^= bvv
                    case _:
                        raise Int3MissingEntityError(f"Unsupported factor op: {op}")

            solver.add(solver_clause == target)

            if solver.check() != sat:
                continue

            # We got a sat result!
            model = solver.model()

            if start_with_bvv:
                start_value = start_bv.as_long()
            else:
                start_value = model[start_bv].as_long()

            factor_clauses = [FactorClause(FactorOperation.Init, start_value)]
            for var, op in zip(var_list[1:], op_product):
                factor_clauses.append(FactorClause(op, model[var].as_long()))

            return FactorResult(clauses=tuple(factor_clauses))
    else:
        raise Int3SatError(
            f"Unable to solve for target value {target} up to depth {depth}"
        )


def _add_bad_byte_constraints(
    solver: Solver, var: Any, ctx: Context, width: int, byte_width: int = 8
):
    for bad_byte in ctx.bad_bytes:
        for i in range(0, width, byte_width):
            solver.add(Extract(i + byte_width - 1, i, var) != bad_byte)
