from dataclasses import dataclass

from .variable import IrBytesVariable, IrIntVariable


@dataclass
class IrIntConstant(IrIntVariable):
    value: int


@dataclass
class IrBytesConstant(IrBytesVariable):
    value: bytes
