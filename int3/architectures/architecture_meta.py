import platform
import struct
import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import ClassVar, cast

from capstone import (
    CS_ARCH_MIPS,
    CS_ARCH_X86,
    CS_MODE_32,
    CS_MODE_64,
    CS_MODE_BIG_ENDIAN,
    CS_MODE_MIPS32,
)
from keystone import (
    KS_ARCH_MIPS,
    KS_ARCH_X86,
    KS_MODE_32,
    KS_MODE_64,
    KS_MODE_BIG_ENDIAN,
    KS_MODE_MIPS32,
)

from int3.errors import (
    Int3ArgumentError,
    Int3InsufficientWidthError,
    Int3MissingEntityError,
)

from .endian import Endian
from .instruction_width import InstructionWidth
from .registers import (
    MipsGpRegisters,
    MipsRegisters,
    x86_64GpRegisters,
    x86_64Registers,
    x86GpRegisters,
    x86Registers,
)

_width_to_format_str_map = {
    0x8: "b",
    0x10: "h",
    0x20: "l",
    0x40: "q",
}

_endian_to_format_str_map = {
    Endian.Big: ">",
    Endian.Little: "<",
}


@dataclass(frozen=True)
class ArchitectureMeta:
    name: str
    bit_size: int
    endian: Endian
    instruction_width: InstructionWidth

    regs: tuple[str, ...]
    gp_regs: tuple[str, ...]
    sp_reg: str

    toolchain_triple: str
    qemu_name: str
    linux_kernel_name: str

    keystone_arch: int
    keystone_mode: int

    capstone_arch: int
    capstone_mode: int

    byte_size: int = field(init=False)

    BITS_IN_A_BYTE: ClassVar[int] = 8

    def __post_init__(self):
        object.__setattr__(self, "byte_size", self.bit_size // self.BITS_IN_A_BYTE)

    def is_okay_value(self, imm: int) -> bool:
        """Tests whether a value can be represented on this architecture."""
        return imm.bit_length() <= self.bit_size

    def _make_struct_format_str(self, width: int | None = None, signed: bool = False):
        if width is None:
            width = self.bit_size
        elif width > self.bit_size:
            raise Int3InsufficientWidthError(
                f"Architecture {self.__class__.__name__} cannot represent width {width}"
            )

        endian_format = _endian_to_format_str_map.get(self.endian, None)
        if endian_format is None:
            raise Int3ArgumentError(f"Invalid endianness: {self.endian}")

        width_format = _width_to_format_str_map.get(width, None)
        if width_format is None:
            raise Int3InsufficientWidthError(f"Invalid width: {width}")

        if not signed:
            width_format = width_format.upper()

        return f"{endian_format}{width_format}"

    def pad(
        self, value: bytes, width: int | None = None, fill_byte: bytes = b"\x00"
    ) -> bytes:
        if width is None:
            width = self.bit_size

        byte_width = width // self.BITS_IN_A_BYTE

        if len(value) > byte_width:
            raise Int3InsufficientWidthError(
                f"Value {value!r} already exceeds width of {byte_width}"
            )
        elif len(value) == byte_width:
            return value

        if self.endian == Endian.Little:
            return value.ljust(byte_width, fill_byte)
        else:
            return value.rjust(byte_width, fill_byte)

    def pack(self, value: int, width: int | None = None) -> bytes:
        if not self.is_okay_value(value):
            raise Int3InsufficientWidthError(
                f"Architecture {self.__class__.__name__} cannot hold value {value}"
            )

        signed = value < 0

        format_str = self._make_struct_format_str(width=width, signed=signed)
        try:
            return struct.pack(format_str, value)
        except struct.error as e:
            raise Int3InsufficientWidthError(
                f"Unable to pack {value} using fmt string {format_str}"
            ) from e

    def unpack(
        self, data: bytes, width: int | None = None, signed: bool = False
    ) -> int:
        format_str = self._make_struct_format_str(width=width, signed=signed)
        try:
            return cast(int, struct.unpack(format_str, data)[0])
        except struct.error as e:
            raise Int3InsufficientWidthError(
                f"Unable to unpack {len(data)} bytes using fmt string {format_str}"
            ) from e


class ArchitectureMetas(Enum):
    # Reference:
    # https://github.com/keystone-engine/keystone/blob/master/bindings/python/sample.py

    x86 = ArchitectureMeta(
        name="x86",
        bit_size=32,
        endian=Endian.Little,
        instruction_width=InstructionWidth.Variable,
        regs=x86Registers,
        gp_regs=x86GpRegisters,
        sp_reg="esp",
        toolchain_triple="i686-linux-musl",
        qemu_name="i386",
        linux_kernel_name="i386",
        keystone_arch=KS_ARCH_X86,
        keystone_mode=KS_MODE_32,
        capstone_arch=CS_ARCH_X86,
        capstone_mode=CS_MODE_32,
    )
    x86_64 = ArchitectureMeta(
        name="x86_64",
        bit_size=64,
        endian=Endian.Little,
        instruction_width=InstructionWidth.Variable,
        regs=x86_64Registers,
        gp_regs=x86_64GpRegisters,
        sp_reg="rsp",
        toolchain_triple="x86_64-linux-musl",
        qemu_name="x86_64",
        linux_kernel_name="x86_64",
        keystone_arch=KS_ARCH_X86,
        keystone_mode=KS_MODE_64,
        capstone_arch=CS_ARCH_X86,
        capstone_mode=CS_MODE_64,
    )
    Mips = ArchitectureMeta(
        name="mips",
        bit_size=32,
        endian=Endian.Big,
        instruction_width=InstructionWidth.Fixed,
        regs=MipsRegisters,
        gp_regs=MipsGpRegisters,
        sp_reg="$sp",
        toolchain_triple="mips-linux-musl",
        qemu_name="mips",
        linux_kernel_name="mipso32",
        keystone_arch=KS_ARCH_MIPS,
        keystone_mode=KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN,
        capstone_arch=CS_ARCH_MIPS,
        capstone_mode=CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN,
    )

    @staticmethod
    def from_host() -> ArchitectureMeta:
        # References:
        # https://stackoverflow.com/a/45125525
        # https://en.wikipedia.org/wiki/Uname

        is_little_endian = sys.byteorder == "little"

        match (machine := platform.machine()):
            case "i386":
                return ArchitectureMetas.from_str("x86")
            case "x86_64":
                return ArchitectureMetas.from_str("x86_64")
            case "mips":
                if is_little_endian:
                    return ArchitectureMetas.from_str("Mipsel")
                else:
                    return ArchitectureMetas.from_str("Mips")
            case _:
                raise Int3MissingEntityError(f"Unrecognized machine {machine}")

    @staticmethod
    def from_str(architecture_name: str) -> ArchitectureMeta:
        architecture = _ARCHITECTURE_MAP.get(architecture_name, None)
        if architecture is None:
            raise Int3MissingEntityError(f"No such architecture {architecture_name}")

        return architecture

    @staticmethod
    def names() -> list[str]:
        return list(_ARCHITECTURE_MAP.keys())


_ARCHITECTURE_MAP: dict[str, ArchitectureMeta] = {
    architecture_enum.value.name: architecture_enum.value
    for architecture_enum in ArchitectureMetas
}
