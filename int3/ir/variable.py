from __future__ import annotations

from dataclasses import dataclass, field

from .branch import IrBranch, IrBranchOperator

VAR_UNNAMED = "<<unnamed>>"


@dataclass
class IrIntVariable:
    signed: bool
    bit_size: int

    name: str = field(init=False, default=VAR_UNNAMED)
    is_unbound: bool = field(init=False, default=False)

    def is_representable(self, value: int) -> bool:
        if self.signed:
            magnitude = 1 << (self.bit_size - 1)
            return -magnitude <= value <= (magnitude - 1)
        else:
            return 0 <= value <= ((1 << self.bit_size) - 1)

    @property
    def is_unnamed(self) -> bool:
        return self.name == VAR_UNNAMED

    def _ensure_int_var(self, var: AnyIntType) -> IrIntType:
        if isinstance(var, int):
            return IrIntConstant(signed=self.signed, bit_size=self.bit_size, value=var)
        else:
            return var

    def __str__(self) -> str:
        signedness = "i" if self.signed else "u"
        return f"{signedness}{self.bit_size}"

    def __lt__(self, other: AnyIntType) -> IrBranch:
        other_var = self._ensure_int_var(other)

        return IrBranch(
            operator=IrBranchOperator.LessThan,
            args=[self, other_var],
        )

    @staticmethod
    def i8() -> IrIntVariable:
        return IrIntVariable(signed=True, bit_size=8)

    @staticmethod
    def i16() -> IrIntVariable:
        return IrIntVariable(signed=True, bit_size=16)

    @staticmethod
    def i32() -> IrIntVariable:
        return IrIntVariable(signed=True, bit_size=32)

    @staticmethod
    def i64() -> IrIntVariable:
        return IrIntVariable(signed=True, bit_size=64)

    @staticmethod
    def u8() -> IrIntVariable:
        return IrIntVariable(signed=False, bit_size=8)

    @staticmethod
    def u16() -> IrIntVariable:
        return IrIntVariable(signed=False, bit_size=16)

    @staticmethod
    def u32() -> IrIntVariable:
        return IrIntVariable(signed=False, bit_size=32)

    @staticmethod
    def u64() -> IrIntVariable:
        return IrIntVariable(signed=False, bit_size=64)


@dataclass
class IrBytesVariable:
    # TODO: Length field
    name: str

    is_unbound: bool = field(init=False, default=False)


@dataclass
class IrIntConstant(IrIntVariable):
    value: int


@dataclass
class IrBytesConstant(IrBytesVariable):
    value: bytes


type IrVariable = IrBytesVariable | IrIntVariable
type IrConstant = IrBytesConstant | IrIntConstant

type IrIntType = IrIntConstant | IrIntVariable
type IrBytesType = IrBytesConstant | IrBytesVariable

type AnyIntType = IrIntType | int
type AnyBytesType = IrIntType | bytes
