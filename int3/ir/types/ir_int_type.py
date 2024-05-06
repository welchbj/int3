from __future__ import annotations

from dataclasses import dataclass

from .ir_type import IrType


@dataclass(frozen=True)
class IrIntType(IrType):
    signed: bool
    bit_size: int

    def is_representable(self, value: int) -> bool:
        if self.signed:
            magnitude = 1 << (self.bit_size - 1)
            return -magnitude <= value <= (magnitude - 1)
        else:
            return 0 <= value <= ((1 << self.bit_size) - 1)

    @staticmethod
    def i8() -> IrIntType:
        return IrIntType(signed=True, bit_size=8)

    @staticmethod
    def i16() -> IrIntType:
        return IrIntType(signed=True, bit_size=16)

    @staticmethod
    def i32() -> IrIntType:
        return IrIntType(signed=True, bit_size=32)

    @staticmethod
    def i64() -> IrIntType:
        return IrIntType(signed=True, bit_size=64)

    @staticmethod
    def u8() -> IrIntType:
        return IrIntType(signed=False, bit_size=8)

    @staticmethod
    def u16() -> IrIntType:
        return IrIntType(signed=False, bit_size=16)

    @staticmethod
    def u32() -> IrIntType:
        return IrIntType(signed=False, bit_size=32)

    @staticmethod
    def u64() -> IrIntType:
        return IrIntType(signed=False, bit_size=64)
