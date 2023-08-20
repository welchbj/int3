from dataclasses import dataclass
from typing import TYPE_CHECKING, Sequence

from z3 import BitVecVal, Solver

from .factor_constraint import FactorConstraintCallbackContext
from .factor_operation import FactorOperation

if TYPE_CHECKING:
    from int3.context import Context


@dataclass(frozen=True)
class FactorContext:
    # The wrapped int3 Context instance.
    ctx: "Context"

    # The target value.
    target: int

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

    def do_arch_constraint_cb(
        self, solver: Solver, op: FactorOperation, bvv: BitVecVal
    ):
        return self.ctx.architecture.factor_constraint_cb(
            FactorConstraintCallbackContext(
                factor_ctx=self,
                solver=solver,
                factor_operation=op,
                bvv_operand=bvv,
            )
        )
