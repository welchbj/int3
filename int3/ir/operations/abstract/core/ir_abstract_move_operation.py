from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..ir_abstract_operation import IrAbstractOperation

if TYPE_CHECKING:
    from ....variables import IrVar


@dataclass
class IrAbstractMoveOperation(IrAbstractOperation):
    source: "IrVar"
    sink: "IrVar"

    # TODO: Should we be enforcing the types of the two operands here?

    def __str__(self) -> str:
        return f"move {self.sink} {self.source}"
