from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from z3 import BitVecVal, Solver

from .factor_operation import FactorOperation

if TYPE_CHECKING:
    from .factor_context import FactorContext


@dataclass
class FactorConstraintCallbackContext:
    factor_ctx: "FactorContext"
    solver: Solver

    factor_operation: FactorOperation
    bvv_operand: BitVecVal


class FactorConstraintCallback(Protocol):
    def __call__(self, ctx: FactorConstraintCallbackContext):
        ...
