from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from int3._interfaces import PrintableIr

from .hlir_branch import HlirBranch, HlirBranchOperator

if TYPE_CHECKING:
    from int3.compilation import Compiler


@dataclass
class _HlirIntBase:
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
class HlirIntVariable(_HlirIntBase, PrintableIr):
    name: str
    is_unbound: bool = field(init=False, default=False)

    def _ensure_int_var(self, var: HlirAnyIntType) -> HlirIntType:
        if isinstance(var, int):
            return self.compiler._make_int_var(
                signed=self.signed, bit_size=self.bit_size, value=var
            )
        else:
            return var

    def to_str(self, indent: int = 0) -> str:
        indent_str = self.indent_str(indent)
        return f"{indent_str}{self.name}/{self.type_str}"

    def __lt__(self, other: HlirAnyIntType) -> HlirBranch:
        other_var = self._ensure_int_var(other)

        return HlirBranch(
            operator=HlirBranchOperator.LessThan,
            args=[self, other_var],
        )


@dataclass
class HlirIntConstant(_HlirIntBase, PrintableIr):
    value: int

    def to_str(self, indent: int = 0) -> str:
        indent_str = self.indent_str(indent)
        return f"{indent_str}{self.value:#x}/{self.type_str}"


@dataclass
class HlirBytesVariable:
    name: str
    is_unbound: bool = field(init=False, default=False)


@dataclass
class HlirBytesConstant(HlirBytesVariable):
    value: bytes


type HlirVariable = HlirBytesVariable | HlirIntVariable
type HlirConstant = HlirBytesConstant | HlirIntConstant

type HlirIntType = HlirIntConstant | HlirIntVariable
type HlirBytesType = HlirBytesConstant | HlirBytesVariable

type HlirAnyIntType = HlirIntType | int
type HlirAnyBytesType = HlirIntType | bytes
type HlirAnyType = HlirBytesType | HlirIntType
