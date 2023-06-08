import platform
from dataclasses import dataclass
from enum import Enum, auto

from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from keystone import KS_ARCH_X86, KS_MODE_32, KS_MODE_64

from int3.errors import Int3MissingEntityError


class Endian(Enum):
    Big = auto()
    Little = auto()


class StackGrowth(Enum):
    Down = auto()
    Up = auto()


@dataclass(frozen=True)
class Architecture:
    name: str
    bit_size: int
    endian: Endian
    stack_growth: StackGrowth

    keystone_arch: int
    keystone_mode: int

    capstone_arch: int
    capstone_mode: int


class Architectures(Enum):
    x86 = Architecture(
        name="x86",
        bit_size=32,
        endian=Endian.Little,
        stack_growth=StackGrowth.Down,
        keystone_arch=KS_ARCH_X86,
        keystone_mode=KS_MODE_32,
        capstone_arch=CS_ARCH_X86,
        capstone_mode=CS_MODE_32,
    )
    x86_64 = Architecture(
        name="x86_64",
        bit_size=64,
        endian=Endian.Little,
        stack_growth=StackGrowth.Down,
        keystone_arch=KS_ARCH_X86,
        keystone_mode=KS_MODE_64,
        capstone_arch=CS_ARCH_X86,
        capstone_mode=CS_MODE_64,
    )

    @staticmethod
    def from_host() -> Architecture:
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
