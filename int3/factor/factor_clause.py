from dataclasses import dataclass

from int3.errors import Int3MissingEntityError

from .factor_operation import FactorOperation


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
            case FactorOperation.Neg:
                s += "~"
            case _:
                raise Int3MissingEntityError(f"Unexpected factor op: {self.operation}")

        if self.operation != FactorOperation.Neg:
            s += hex(self.operand)

        return s
