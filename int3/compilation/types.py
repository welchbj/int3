from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, cast

from llvmlite import ir as llvmir

from int3.errors import Int3InsufficientWidthError

if TYPE_CHECKING:
    from .compiler import Compiler


@dataclass
class TypeManager:
    """Manager for int3 high-level types."""

    compiler: "Compiler"

    void: VoidType = field(init=False)

    inat: IntType = field(init=False)
    unat: IntType = field(init=False)

    i8: IntType = field(init=False)
    i16: IntType = field(init=False)
    i32: IntType = field(init=False)
    i64: IntType = field(init=False)

    u8: IntType = field(init=False)
    u16: IntType = field(init=False)
    u32: IntType = field(init=False)
    u64: IntType = field(init=False)

    def __post_init__(self):
        self.void = VoidType()

        native_bit_size = self.compiler.arch.bit_size
        self.inat = IntType(bit_size=native_bit_size, is_signed=True)
        self.unat = IntType(bit_size=native_bit_size, is_signed=False)

        self.i8 = IntType(bit_size=8, is_signed=True)
        self.i16 = IntType(bit_size=16, is_signed=True)
        self.i32 = IntType(bit_size=32, is_signed=True)
        self.i64 = IntType(bit_size=64, is_signed=True)

        self.u8 = IntType(bit_size=8, is_signed=False)
        self.u16 = IntType(bit_size=16, is_signed=False)
        self.u32 = IntType(bit_size=32, is_signed=False)
        self.u64 = IntType(bit_size=64, is_signed=False)


@dataclass(frozen=True)
class VoidType:
    wrapped_type: llvmir.VoidType = field(init=False, default_factory=llvmir.VoidType)


@dataclass(frozen=True)
class IntType:
    """Wrapper around an LLVM integer type.

    For a good overview of LLVM IR int types, see:
    https://stackoverflow.com/a/14723945

    """

    bit_size: int
    is_signed: bool

    wrapped_type: llvmir.IntType = field(init=False)
    max_value: int = field(init=False)
    min_value: int = field(init=False)

    def __post_init__(self):
        object.__setattr__(self, "wrapped_type", llvmir.IntType(bits=self.bit_size))
        object.__setattr__(self, "max_value", self._max_value())
        object.__setattr__(self, "min_value", self._min_value())

    def __str__(self) -> str:
        sign_str = "i" if self.is_signed else "u"
        return f"{sign_str}{self.bit_size}"

    def can_represent_value(self, value: int) -> bool:
        return self.min_value <= value <= self.max_value

    def can_represent_type(self, other: IntType) -> bool:
        return self.min_value <= other.min_value and self.max_value >= other.max_value

    def _max_value(self) -> int:
        if self.is_signed:
            magnitude = 1 << (self.bit_size - 1)
            return magnitude - 1
        else:
            return (1 << self.bit_size) - 1

    def _min_value(self) -> int:
        if self.is_signed:
            magnitude = 1 << (self.bit_size - 1)
            return -magnitude
        else:
            return 0


@dataclass
class _IntBase:
    """Base class for IntConstant and IntVariable.

    Implements Python magic methods for various integer arithemtic and
    bitwise operations.

    """

    compiler: "Compiler"
    type: IntType
    wrapped_llvm_node: llvmir.Constant | llvmir.Instruction

    def make_int(self, value: int) -> IntConstant:
        """Create an IntConstant of the same type."""
        return self.compiler.make_int(value=value, type=self.type)

    def __add__(self, other: IntArgType) -> IntVariable:
        return self.compiler.add(cast(IntValueType, self), other)


@dataclass
class IntConstant(_IntBase):
    value: int

    def __post_init__(self):
        if not self.type.can_represent_value(self.value):
            raise Int3InsufficientWidthError(
                f"{self.type} cannot represent value {self.value:#x}"
            )


@dataclass
class IntVariable(_IntBase):
    pass


@dataclass
class TypeCoercion:
    result_type: IntType
    args: list[IntValueType]


type IntValueType = IntVariable | IntConstant
type IntArgType = IntValueType | int
type ReturnType = IntType | VoidType
type ArgType = IntArgType
