import itertools
from dataclasses import replace
from typing import Any, cast

from z3 import (
    BitVec,
    BitVecVal,
    BVAddNoOverflow,
    BVSNegNoOverflow,
    BVSubNoOverflow,
    BVSubNoUnderflow,
    Extract,
    Solver,
    sat,
)

from int3.errors import Int3ArgumentError, Int3MissingEntityError, Int3SatError

from .factor_clause import FactorClause
from .factor_context import FactorContext
from .factor_operation import FactorOperation
from .factor_result import FactorResult


def compute_factor(
    factor_ctx: FactorContext,
) -> FactorResult:
    """Emit sets of operations that achieve the target value.

    The `start` argument may specify an initial start value. When omitted, one
    will be selected by the SAT engine.

    """
    if factor_ctx.max_depth < 1:
        raise Int3ArgumentError(
            f"max_depth must be a positive int ({factor_ctx.max_depth} is not)"
        )

    # Check if a bad byte was provided in the start value.
    if factor_ctx.start is not None:
        packed_start = factor_ctx.arch.pack(factor_ctx.start, width=factor_ctx.width)
        if any(b in packed_start for b in factor_ctx.bad_bytes):
            raise Int3ArgumentError(
                f"Specified start value {hex(factor_ctx.start)} contains at least one "
                "bad byte"
            )

    forbidden_ops_iter = (
        tuple() if factor_ctx.forbidden_ops is None else tuple(factor_ctx.forbidden_ops)
    )

    # Init is implied to always be allowed, since we have to start with some
    # value.
    if FactorOperation.Init in forbidden_ops_iter:
        raise Int3ArgumentError(f"{FactorOperation.Init} cannot be forbidden")

    base_allowed_ops: tuple[FactorOperation, ...]
    if factor_ctx.allowed_ops is None:
        base_allowed_ops = (
            FactorOperation.Add,
            FactorOperation.Sub,
            FactorOperation.Xor,
        )
    else:
        base_allowed_ops = tuple(factor_ctx.allowed_ops)

    # Using a tuple rather than set differences to preserve order in allowed_ops.
    factor_ctx = replace(
        factor_ctx,
        allowed_ops=tuple(
            op for op in base_allowed_ops if op not in forbidden_ops_iter
        ),
    )

    # Default the width to the passed context.
    if factor_ctx.width is None:
        factor_ctx = replace(factor_ctx, width=factor_ctx.arch.bit_size)

    width_as_int = cast(int, factor_ctx.width)
    if (num_target_bits := factor_ctx.target.bit_length()) > width_as_int:
        raise Int3ArgumentError(
            f"Target would require {num_target_bits} bits to represent, "
            f"but we are using a width of {factor_ctx.width}"
        )

    allowed_ops = cast(tuple[FactorOperation, ...], factor_ctx.allowed_ops)

    for depth in range(1, factor_ctx.max_depth + 1):
        for op_product in itertools.product(allowed_ops, repeat=depth):
            solver = Solver()

            if factor_ctx.start is None:
                start_with_bvv = False
                start_bv = BitVec("start", factor_ctx.width)
            else:
                start_with_bvv = True
                start_bv = BitVecVal(factor_ctx.start, factor_ctx.width)

                # XXX
                # factor_ctx.do_arch_constraint_cb(
                #     solver, FactorOperation.Init, start_bv
                # )

            var_list = [start_bv]
            var_list.extend(BitVec(f"s{i}", factor_ctx.width) for i in range(depth))

            bv_list = var_list[1:] if start_with_bvv else var_list
            for bvv in bv_list:
                _add_bad_byte_constraints(factor_ctx, solver, bvv)

            solver_clause = var_list[0]

            for bvv, op in zip(var_list[1:], op_product):
                # XXX
                # Invoke callback to allow for the addition of per-architecture
                # constraints.
                # factor_ctx.do_arch_constraint_cb(solver, op, bvv)

                match op:
                    case FactorOperation.Add:
                        if not factor_ctx.allow_overflow:
                            solver.add(
                                BVAddNoOverflow(solver_clause, bvv, signed=False)
                            )

                        solver_clause += bvv
                    case FactorOperation.Sub:
                        if not factor_ctx.allow_overflow:
                            solver.add(BVSubNoOverflow(solver_clause, bvv))
                            solver.add(
                                BVSubNoUnderflow(solver_clause, bvv, signed=False)
                            )

                        solver_clause -= bvv
                    case FactorOperation.Xor:
                        solver_clause ^= bvv
                    case FactorOperation.Neg:
                        if not factor_ctx.allow_overflow:
                            solver.add(BVSNegNoOverflow(solver_clause))

                        solver_clause = ~solver_clause
                    case _:
                        raise Int3MissingEntityError(f"Unsupported factor op: {op}")

            solver.add(solver_clause == factor_ctx.target)

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
            f"Unable to solve for target value {factor_ctx.target} up to depth {depth}"
        )


def _add_bad_byte_constraints(factor_ctx: FactorContext, solver: Solver, var: Any):
    width = cast(int, factor_ctx.width)

    for bad_byte in factor_ctx.bad_bytes:
        for i in range(0, width, factor_ctx.byte_width):
            solver.add(Extract(i + factor_ctx.byte_width - 1, i, var) != bad_byte)
