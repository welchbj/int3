from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from int3._interfaces import PrintableIr

from .branch import IrBranch, IrBranchOperator

if TYPE_CHECKING:
    from int3.compilation import Compiler


@dataclass
class _IrIntBase:
    compiler: "Compiler"
    signed: bool
    bit_size: int

    def is_representable(self, value: int) -> bool:
        if self.signed:
            magnitude = 1 << (self.bit_size - 1)
            return -magnitude <= value <= (magnitude - 1)
        else:
            return 0 <= value <= ((1 << self.bit_size) - 1)

    @property
    def type_str(self) -> str:
        signedness = "i" if self.signed else "u"
        return f"{signedness}{self.bit_size}"


@dataclass
class IrIntVariable(_IrIntBase, PrintableIr):
    name: str
    is_unbound: bool = field(init=False, default=False)

    def _ensure_int_var(self, var: AnyIntType) -> IrIntType:
        if isinstance(var, int):
            return self.compiler._make_int_var(
                signed=self.signed, bit_size=self.bit_size, value=var
            )
        else:
            return var

    def to_str(self, indent: int = 0) -> str:
        indent_str = self.indent_str(indent)
        return f"{indent_str}{self.name}/{self.type_str}"

    def __lt__(self, other: AnyIntType) -> IrBranch:
        other_var = self._ensure_int_var(other)

        return IrBranch(
            operator=IrBranchOperator.LessThan,
            args=[self, other_var],
        )


@dataclass
class IrIntConstant(_IrIntBase, PrintableIr):
    value: int

    def to_str(self, indent: int = 0) -> str:
        indent_str = self.indent_str(indent)
        return f"{indent_str}{self.value:#x}/{self.type_str}"


@dataclass
class IrBytesVariable:
    name: str
    is_unbound: bool = field(init=False, default=False)


@dataclass
class IrBytesConstant(IrBytesVariable):
    value: bytes


type IrVariable = IrBytesVariable | IrIntVariable
type IrConstant = IrBytesConstant | IrIntConstant

type IrIntType = IrIntConstant | IrIntVariable
type IrBytesType = IrBytesConstant | IrBytesVariable

type AnyIntType = IrIntType | int
type AnyBytesType = IrIntType | bytes
type AnyIrType = IrBytesType | IrIntType
