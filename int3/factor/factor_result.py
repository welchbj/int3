from dataclasses import dataclass

from .factor_clause import FactorClause
from .factor_operation import FactorOperation


@dataclass(frozen=True)
class FactorResult:
    clauses: tuple[FactorClause, ...]

    def __str__(self) -> str:
        last_element_idx = len(self.clauses) - 1

        s = ""
        for idx, clause in enumerate(self.clauses):
            if clause.operation == FactorOperation.Neg:
                s = f"{str(clause)}({s})"
            else:
                s += str(clause)

            if (
                idx < last_element_idx
                and self.clauses[idx + 1].operation != FactorOperation.Neg
            ):
                s += " "

        return s
