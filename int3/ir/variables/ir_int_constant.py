from __future__ import annotations

from dataclasses import dataclass

from int3.errors import Int3IrMismatchedTypeError

from ..operations import IrAbstractLtPredicate
from ..types import IrIntType
from .ir_var import IrVar


@dataclass
class IrIntConstant(IrVar):
    value: int

    def __post_init__(self):
        if not isinstance(self.type_, IrIntType):
            raise Int3IrMismatchedTypeError(
                f"Provided value is {type(self.value)} but IR type is {self.type_}"
            )

        if not self.type_.is_representable(self.value):
            raise Int3IrMismatchedTypeError(
                f"Cannot represent {self.value} with {self.type_}"
            )

    def maybe_promote_int(self, other: int | IrVar) -> IrVar:
        """Maybe promote a raw integer to our type.

        If `other` is already an `IrVar`, then it will simply be returned.

        """
        if isinstance(other, int):
            return IrIntConstant(type_=self.type_, value=other)
        else:
            return other

    def __lt__(self, other: int | IrVar) -> IrAbstractLtPredicate:
        return IrAbstractLtPredicate(self, self.maybe_promote_int(other))

    # TODO: Remaining mathematical operations.

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
