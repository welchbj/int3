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
from .registers import RegisterDef, Registers

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
    insn_width_flavor: InstructionWidth
    min_insn_width: int

    toolchain_triple: str
    qemu_name: str
    linux_kernel_name: str
    ghidra_name: str
    # See: https://stackoverflow.com/a/39114754
    clang_name: str
    llvm_reg_prefix: str

    keystone_arch: int
    keystone_mode: int

    capstone_arch: int
    capstone_mode: int

    sp_reg: RegisterDef
    gp_regs: tuple[RegisterDef, ...]
    reg_clobber_groups: tuple[set[RegisterDef], ...]

    byte_size: int = field(init=False)

    _reg_name_map: dict[str, RegisterDef] = field(init=False)
    _reg_clobber_map: dict[RegisterDef, set[RegisterDef]] = field(init=False)

    BITS_IN_A_BYTE: ClassVar[int] = 8

    def __post_init__(self):
        object.__setattr__(self, "byte_size", self.bit_size // self.BITS_IN_A_BYTE)

        # Init _reg_name_map.
        reg_name_map = {}
        reg_name_map[self.sp_reg.name] = self.sp_reg
        for reg in self.gp_regs:
            reg_name_map[reg.name] = reg
        object.__setattr__(self, "_reg_name_map", reg_name_map)

        # Init _reg_clobber_map.
        reg_clobber_map = {}
        for reg_clobber_set in self.reg_clobber_groups:
            for reg in reg_clobber_set:
                reg_clobber_map[reg] = reg_clobber_set
        object.__setattr__(self, "_reg_clobber_map", reg_clobber_map)

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

    def expand_regs(self, *regs: RegisterDef) -> tuple[RegisterDef, ...]:
        """Expand an input set of registers to include all implicit clobbers."""
        reg_list: list[RegisterDef] = []
        for reg in regs:
            reg_list.append(reg)
            reg_list.extend(self._reg_clobber_map[reg])

        # Using dict.fromkeys to emulate an ordered set.
        return tuple(dict.fromkeys(reg_list))

    def reg(self, name: str) -> RegisterDef:
        """Resolve a register definition by name."""
        try:
            return self._reg_name_map[name]
        except KeyError as e:
            raise Int3MissingEntityError(f"No reg {name} for arch {self.name}") from e

    def align_up_to_min_insn_width(self, value: int) -> int:
        while value % self.min_insn_width != 0:
            value += 1

        return value

    def align_down_to_min_insn_width(self, value: int) -> int:
        while value % self.min_insn_width != 0:
            value -= 1

        return value

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


class Architectures(Enum):
    x86 = Architecture(
        name="x86",
        bit_size=32,
        endian=Endian.Little,
        insn_width_flavor=InstructionWidth.Variable,
        min_insn_width=1,
        toolchain_triple="i686-linux-musl",
        qemu_name="i386",
        linux_kernel_name="i386",
        ghidra_name="x86:LE:32:default",
        clang_name="i386",
        llvm_reg_prefix="%",
        keystone_arch=KS_ARCH_X86,
        keystone_mode=KS_MODE_32,
        capstone_arch=CS_ARCH_X86,
        capstone_mode=CS_MODE_32,
        sp_reg=Registers.x86.esp,
        gp_regs=(
            Registers.x86.ebp,
            Registers.x86.eax,
            # LLVM is doing weird stuff with ebx with regard to function calls.
            #
            # See: https://groups.google.com/g/native-client-discuss/c/a6AAns1nOl4
            # Registers.x86.ebx,
            Registers.x86.ecx,
            Registers.x86.edx,
            Registers.x86.esi,
            Registers.x86.edi,
        ),
        reg_clobber_groups=(
            {Registers.x86.esp, Registers.x86.sp, Registers.x86.spl},
            {Registers.x86.ebp, Registers.x86.bp, Registers.x86.bpl},
            {Registers.x86.eax, Registers.x86.ax, Registers.x86.al},
            {Registers.x86.ebx, Registers.x86.bx, Registers.x86.bl},
            {Registers.x86.ecx, Registers.x86.cx, Registers.x86.cl},
            {Registers.x86.edx, Registers.x86.dx, Registers.x86.dl},
            {Registers.x86.esi, Registers.x86.si, Registers.x86.sil},
            {Registers.x86.edi, Registers.x86.di, Registers.x86.dil},
        ),
    )
    x86_64 = Architecture(
        name="x86_64",
        bit_size=64,
        endian=Endian.Little,
        insn_width_flavor=InstructionWidth.Variable,
        min_insn_width=1,
        toolchain_triple="x86_64-linux-musl",
        qemu_name="x86_64",
        linux_kernel_name="x86_64",
        ghidra_name="x86:LE:64:default",
        clang_name="x86_64",
        llvm_reg_prefix="%",
        keystone_arch=KS_ARCH_X86,
        keystone_mode=KS_MODE_64,
        capstone_arch=CS_ARCH_X86,
        capstone_mode=CS_MODE_64,
        sp_reg=Registers.x86_64.rsp,
        gp_regs=(
            Registers.x86_64.rbp,
            Registers.x86_64.rax,
            Registers.x86_64.rbx,
            Registers.x86_64.rcx,
            Registers.x86_64.rdx,
            Registers.x86_64.rdi,
            Registers.x86_64.rsi,
            Registers.x86_64.r8,
            Registers.x86_64.r9,
            Registers.x86_64.r10,
            Registers.x86_64.r11,
            Registers.x86_64.r12,
            Registers.x86_64.r13,
            Registers.x86_64.r14,
            Registers.x86_64.r15,
        ),
        reg_clobber_groups=(
            {
                Registers.x86_64.rsp,
                Registers.x86_64.esp,
                Registers.x86_64.sp,
                Registers.x86_64.spl,
            },
            {
                Registers.x86_64.rbp,
                Registers.x86_64.ebp,
                Registers.x86_64.bp,
                Registers.x86_64.bpl,
            },
            {
                Registers.x86_64.rax,
                Registers.x86_64.eax,
                Registers.x86_64.ax,
                Registers.x86_64.al,
            },
            {
                Registers.x86_64.rbx,
                Registers.x86_64.ebx,
                Registers.x86_64.bx,
                Registers.x86_64.bl,
            },
            {
                Registers.x86_64.rcx,
                Registers.x86_64.ecx,
                Registers.x86_64.cx,
                Registers.x86_64.cl,
            },
            {
                Registers.x86_64.rdx,
                Registers.x86_64.edx,
                Registers.x86_64.dx,
                Registers.x86_64.dl,
            },
            {
                Registers.x86_64.rdi,
                Registers.x86_64.edi,
                Registers.x86_64.di,
                Registers.x86_64.dil,
            },
            {
                Registers.x86_64.rsi,
                Registers.x86_64.esi,
                Registers.x86_64.si,
                Registers.x86_64.sil,
            },
            {
                Registers.x86_64.r8,
                Registers.x86_64.r8d,
                Registers.x86_64.r8w,
                Registers.x86_64.r8b,
            },
            {
                Registers.x86_64.r9,
                Registers.x86_64.r9d,
                Registers.x86_64.r9w,
                Registers.x86_64.r9b,
            },
            {
                Registers.x86_64.r10,
                Registers.x86_64.r10d,
                Registers.x86_64.r10w,
                Registers.x86_64.r10b,
            },
            {
                Registers.x86_64.r11,
                Registers.x86_64.r11d,
                Registers.x86_64.r11w,
                Registers.x86_64.r11b,
            },
            {
                Registers.x86_64.r12,
                Registers.x86_64.r12d,
                Registers.x86_64.r12w,
                Registers.x86_64.r12b,
            },
            {
                Registers.x86_64.r13,
                Registers.x86_64.r13d,
                Registers.x86_64.r13w,
                Registers.x86_64.r13b,
            },
            {
                Registers.x86_64.r14,
                Registers.x86_64.r14d,
                Registers.x86_64.r14w,
                Registers.x86_64.r14b,
            },
            {
                Registers.x86_64.r15,
                Registers.x86_64.r15d,
                Registers.x86_64.r15w,
                Registers.x86_64.r15b,
            },
        ),
    )
    Mips = Architecture(
        name="mips",
        bit_size=32,
        endian=Endian.Big,
        insn_width_flavor=InstructionWidth.Fixed,
        min_insn_width=4,
        toolchain_triple="mips-linux-musl",
        qemu_name="mips",
        linux_kernel_name="mipso32",
        ghidra_name="MIPS:BE:32:default",
        clang_name="mips",
        llvm_reg_prefix="$$",
        keystone_arch=KS_ARCH_MIPS,
        keystone_mode=KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN,
        capstone_arch=CS_ARCH_MIPS,
        capstone_mode=CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN,
        sp_reg=Registers.Mips.sp,
        gp_regs=(
            Registers.Mips.v0,
            Registers.Mips.v1,
            Registers.Mips.a0,
            Registers.Mips.a1,
            Registers.Mips.a2,
            Registers.Mips.a3,
            Registers.Mips.t0,
            Registers.Mips.t1,
            Registers.Mips.t2,
            Registers.Mips.t3,
            Registers.Mips.t4,
            Registers.Mips.t5,
            Registers.Mips.t6,
            Registers.Mips.t7,
            Registers.Mips.t8,
            Registers.Mips.t9,
            Registers.Mips.s0,
            Registers.Mips.s1,
            Registers.Mips.s2,
            Registers.Mips.s3,
            Registers.Mips.s4,
            Registers.Mips.s5,
            Registers.Mips.s6,
            Registers.Mips.s7,
            Registers.Mips.t8,
            Registers.Mips.t9,
            Registers.Mips.k0,
            Registers.Mips.k1,
        ),
        reg_clobber_groups=tuple(),
    )

    @staticmethod
    def from_host() -> Architecture:
        # References:
        # https://stackoverflow.com/a/45125525
        # https://en.wikipedia.org/wiki/Uname

        is_little_endian = sys.byteorder == "little"

        match machine := platform.machine():
            case "i386":
                return Architectures.from_str("x86")
            case "x86_64":
                return Architectures.from_str("x86_64")
            case "mips":
                if is_little_endian:
                    return Architectures.from_str("Mipsel")
                else:
                    return Architectures.from_str("Mips")
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


_ARCHITECTURE_MAP: dict[str, Architecture] = {
    architecture_enum.value.name: architecture_enum.value
    for architecture_enum in Architectures
}
