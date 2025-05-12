from dataclasses import dataclass


@dataclass(frozen=True)
class IntConstant:
    value: int


@dataclass(frozen=True)
class BytesConstant:
    value: bytes


type Constant = IntConstant | BytesConstant
