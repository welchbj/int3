from __future__ import annotations

from dataclasses import dataclass

from int3.errors import Int3IrMismatchedTypeError

from ..types import IrIntType
from .ir_var import IrVar


@dataclass
class IrIntConstant(IrVar):
    value: int

    def __post_init__(self):
        if not isinstance(self.type_, IrIntType):
            raise Int3IrMismatchedTypeError(
                f"Provided value is {type(self.value)} but IR type is " f"{self.type_}"
            )

        if not self.type_.is_representable(self.value):
            raise Int3IrMismatchedTypeError(
                f"Cannot represent {self.value} with {self.type_}"
            )

    @staticmethod
    def i8(value: int) -> IrIntConstant:
        return IrIntConstant(type_=IrIntType.i8(), value=value)

    @staticmethod
    def i16(value: int) -> IrIntConstant:
        return IrIntConstant(type_=IrIntType.i16(), value=value)

    @staticmethod
    def i32(value: int) -> IrIntConstant:
        return IrIntConstant(type_=IrIntType.i32(), value=value)

    @staticmethod
    def i64(value: int) -> IrIntConstant:
        return IrIntConstant(type_=IrIntType.i64(), value=value)

    @staticmethod
    def u8(value: int) -> IrIntConstant:
        return IrIntConstant(type_=IrIntType.u8(), value=value)

    @staticmethod
    def u16(value: int) -> IrIntConstant:
        return IrIntConstant(type_=IrIntType.u16(), value=value)

    @staticmethod
    def u32(value: int) -> IrIntConstant:
        return IrIntConstant(type_=IrIntType.u32(), value=value)

    @staticmethod
    def u64(value: int) -> IrIntConstant:
        return IrIntConstant(type_=IrIntType.u64(), value=value)
