import platform
import struct
from dataclasses import dataclass
from enum import Enum, auto
from typing import cast

from capstone import CS_ARCH_ARM, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_MODE_ARM
from keystone import KS_ARCH_ARM, KS_ARCH_X86, KS_MODE_32, KS_MODE_64, KS_MODE_ARM

from int3.errors import (
    Int3ArgumentError,
    Int3InsufficientWidthError,
    Int3MissingEntityError,
)
from int3.immediates import IntImmediate

__all__ = ["Endian", "Architecture", "Architectures"]


class Endian(Enum):
    Big = auto()
    Little = auto()


class InstructionWidth(Enum):
    Variable = auto()
    Fixed = auto()


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
class Architecture:
    name: str
    bit_size: int
    endian: Endian
    instruction_width: InstructionWidth

    keystone_arch: int
    keystone_mode: int

    capstone_arch: int
    capstone_mode: int

    def is_okay_value(self, imm: IntImmediate) -> bool:
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


class Architectures(Enum):
    # Reference:
    # https://github.com/keystone-engine/keystone/blob/master/bindings/python/sample.py

    x86 = Architecture(
        name="x86",
        bit_size=32,
        endian=Endian.Little,
        instruction_width=InstructionWidth.Variable,
        keystone_arch=KS_ARCH_X86,
        keystone_mode=KS_MODE_32,
        capstone_arch=CS_ARCH_X86,
        capstone_mode=CS_MODE_32,
    )
    x86_64 = Architecture(
        name="x86_64",
        bit_size=64,
        endian=Endian.Little,
        instruction_width=InstructionWidth.Variable,
        keystone_arch=KS_ARCH_X86,
        keystone_mode=KS_MODE_64,
        capstone_arch=CS_ARCH_X86,
        capstone_mode=CS_MODE_64,
    )
    # TODO: Arm 32-bit immediates are not currently properly handled in SAT logic.
    Arm = Architecture(
        name="arm",
        bit_size=32,
        endian=Endian.Little,
        instruction_width=InstructionWidth.Fixed,
        keystone_arch=KS_ARCH_ARM,
        keystone_mode=KS_MODE_ARM,
        capstone_arch=CS_ARCH_ARM,
        capstone_mode=CS_MODE_ARM,
    )

    @staticmethod
    def from_host() -> Architecture:
        # References:
        # https://stackoverflow.com/a/45125525
        # https://en.wikipedia.org/wiki/Uname

        match (machine := platform.machine()):
            case "i386":
                return Architectures.from_str("x86")
            case "x86_64":
                return Architectures.from_str("x86_64")
            case _:
                raise Int3MissingEntityError(f"Unrecognized machine {machine}")

    @staticmethod
    def from_str(architecture_name: str) -> Architecture:
        architecture = _ARCHITECTURE_MAP.get(architecture_name, None)
        if architecture is None:
            raise Int3MissingEntityError(f"No such architecture {architecture_name}")

        return architecture

    @staticmethod
    def names() -> list[str]:
        return list(_ARCHITECTURE_MAP.keys())


_ARCHITECTURE_MAP = {
    architecture_enum.value.name: architecture_enum.value
    for architecture_enum in Architectures
}
