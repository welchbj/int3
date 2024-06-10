from __future__ import annotations

from dataclasses import dataclass

from int3.errors import Int3IrMismatchedTypeError

from ..types import IrBytesType
from .ir_var import IrVar


@dataclass
class IrBytesConstant(IrVar):
    value: bytes

    def __post_init__(self):
        if not isinstance(self.type_, IrBytesType):
            raise Int3IrMismatchedTypeError(
                f"Provided value is {type(self.value)} but IR type is {self.type_}"
            )

    def __str__(self) -> str:
        return f"{self.value!r}:{self.type_}"
