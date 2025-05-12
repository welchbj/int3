from dataclasses import dataclass


@dataclass(frozen=True)
class IntVariable:
    signed: bool
    width: int


@dataclass(frozen=True)
class BytesVariable: ...


type Variable = IntVariable | BytesVariable
