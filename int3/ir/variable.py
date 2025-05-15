from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class IrIntVariable:
    signed: bool
    bit_size: int

    is_unbound: bool = field(init=False, default=False)

    def is_representable(self, value: int) -> bool:
        if self.signed:
            magnitude = 1 << (self.bit_size - 1)
            return -magnitude <= value <= (magnitude - 1)
        else:
            return 0 <= value <= ((1 << self.bit_size) - 1)

    def __str__(self) -> str:
        signedness = "i" if self.signed else "u"
        return f"{signedness}{self.bit_size}"

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

    is_unbound: bool = field(init=False, default=False)
