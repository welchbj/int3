from dataclasses import dataclass


@dataclass(frozen=True)
class IrIntType:
    signed: bool
    bit_size: int
    value: int
