from dataclasses import dataclass
from enum import Enum, auto
from typing import Sequence

from z3 import BitVec, BitVecVal


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
    width: int,
    depth: int = 2,
    forbidden_ops: Sequence[FactorOperation] | None = None,
    start: int | None = None,
    exhaustive: bool = False,
) -> tuple[FactorResult, ...]:
    """Emit sets of operations that achieve the target value.

    The `start` argument may specify an initial start value. When omitted, one
    will be selected by the SAT engine.

    """
    forbidden_ops_iter = tuple() if forbidden_ops is None else forbidden_ops

    if FactorOperation.Init in forbidden_ops_iter:
        # TODO: Error out.
        pass

    all_ops = (
        FactorOperation.Init,
        FactorOperation.Add,
        FactorOperation.Sub,
        FactorOperation.Xor,
    )

    available_ops = tuple(op for op in all_ops if op not in forbidden_ops_iter)

    if start is None:
        start_var = BitVec("start", width)
    else:
        start_var = BitVecVal(start, width)

    # TODO: Iterate based on the depth.
