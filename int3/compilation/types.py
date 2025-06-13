from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, cast

from int3._vendored.llvmlite import ir as llvmir

from int3.errors import Int3InsufficientWidthError

if TYPE_CHECKING:
    from .compiler import Compiler


@dataclass
class TypeManager:
    """Manager for int3 high-level types."""

    compiler: "Compiler"

    void: VoidType = field(init=False)
    ptr: PointerType = field(init=False)

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
        self.ptr = PointerType()

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
    """Wrapper around the LLVM IR void type."""

    wrapped_type: llvmir.VoidType = field(init=False, default_factory=llvmir.VoidType)


@dataclass(frozen=True)
class PointerType:
    """Wrapper around an LLVM IR opaque pointer type."""

    wrapped_type: llvmir.PointerType = field(default_factory=llvmir.PointerType)


@dataclass
class Pointer:
    """Wrapper around an opaque pointer value."""

    compiler: "Compiler"
    type: PointerType
    wrapped_llvm_node: llvmir.Instruction


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

    def __add__(self, other: PyIntArgType) -> IntVariable:
        return self.compiler.add(cast(PyIntValueType, self), other)


@dataclass
class IntConstant(_IntBase):
    value: int

    def __post_init__(self):
        if not self.type.can_represent_value(self.value):
            raise Int3InsufficientWidthError(
                f"{self.type} cannot represent value {self.value:#x}"
            )


@dataclass
class BytesPointer:
    compiler: "Compiler"
    len_: int

    symtab_index: int = field(init=False)

    @property
    def wrapped_llvm_node(self) -> llvmir.Instruction:
        compiler = self.compiler

        def _make_gep_idx(value: int) -> llvmir.Constant:
            return compiler.i32(value).wrapped_llvm_node

        # Emit stub that loads a pointer to this bytes pointer from the symtab.
        compiler.builder.comment(
            f"Load bytes pointer of length {self.len_} from slot {self.symtab_index}"
        )
        symtab_ptr = compiler.current_func.raw_symtab_ptr
        indices = [_make_gep_idx(self.symtab_index)]
        raw_bytes_ptr_ptr = compiler.builder.gep(
            ptr=symtab_ptr,
            indices=indices,
            source_etype=compiler.types.ptr.wrapped_type,
        )
        raw_bytes_ptr = compiler.builder.load(
            raw_bytes_ptr_ptr, typ=compiler.types.ptr.wrapped_type
        )

        return raw_bytes_ptr

    @property
    def aligned_len(self) -> int:
        """Length of this bytes view aligned to the compiler's native width."""
        reg_size = self.compiler.arch.byte_size
        padding_len = reg_size - (self.len_ % reg_size)
        return self.len_ + padding_len

    def __post_init__(self):
        self.symtab_index = self.compiler.reserve_symbol_index()

    def __len__(self) -> int:
        return self.len_


@dataclass
class IntVariable(_IntBase):
    pass


@dataclass
class TypeCoercion:
    result_type: IntType
    args: list[PyIntValueType]


# Types intended for the user-facing Python API.
type PyIntValueType = IntVariable | IntConstant
type PyBytesValueType = BytesPointer
type PyIntArgType = PyIntValueType | int
type PyBytesArgType = PyBytesValueType | bytes
type PyArgType = PyIntArgType | PyBytesArgType | Pointer
type PyReturnType = IntVariable | IntConstant

# Types intended for defining LLVM IR related constructs.
type IrArgType = IntType | PointerType
type IrReturnType = IntType | PointerType | VoidType
