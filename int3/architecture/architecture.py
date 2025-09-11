import platform
import struct
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import ClassVar, cast

from capstone import (
    CS_ARCH_ARM,
    CS_ARCH_ARM64,
    CS_ARCH_MIPS,
    CS_ARCH_X86,
    CS_MODE_32,
    CS_MODE_64,
    CS_MODE_ARM,
    CS_MODE_BIG_ENDIAN,
    CS_MODE_LITTLE_ENDIAN,
    CS_MODE_MIPS32,
)
from keystone import (
    KS_ARCH_ARM,
    KS_ARCH_ARM64,
    KS_ARCH_MIPS,
    KS_ARCH_X86,
    KS_MODE_32,
    KS_MODE_64,
    KS_MODE_ARM,
    KS_MODE_BIG_ENDIAN,
    KS_MODE_LITTLE_ENDIAN,
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
    """Metadata for a specific computing architecture.

    Names referring to the same architecture are often fragmented across different
    low-level tools and libraries (the Linux kernel, LLVM/Clang, Keystone/Capstone,
    and so on). This class centralizes that information along with the registers
    belonging to an architecture and other relevant metadata needed for proper code
    and program generation.

    An architecture instance servers as the main interface for size-aware integer
    packing and unpacking utilities.

    An architecture instance also provides the simplest interface for accessing the
    architecture's registers and unmasking their aliases and clobbers via the
    ``expand_regs`` and ``reg`` methods.

    """

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
    keystone_reg_prefix: str

    keystone_arch: int
    keystone_mode: int

    capstone_arch: int
    capstone_mode: int

    reg_cls: type
    reg_clobber_groups: tuple[set[RegisterDef], ...]

    byte_size: int = field(init=False)
    regs: tuple[RegisterDef, ...] = field(init=False)

    _reg_name_map: dict[str, RegisterDef] = field(init=False)
    _reg_clobber_map: dict[RegisterDef, set[RegisterDef]] = field(init=False)

    BITS_IN_A_BYTE: ClassVar[int] = 8

    def __post_init__(self):
        object.__setattr__(self, "byte_size", self.bit_size // self.BITS_IN_A_BYTE)

        # Init regs tuple.
        regs = tuple(
            getattr(self.reg_cls, attr)
            for attr in dir(self.reg_cls)
            if not attr.startswith("__")
        )
        object.__setattr__(self, "regs", regs)

        # Init _reg_name_map.
        reg_name_map = {reg.name: reg for reg in self.regs}
        object.__setattr__(self, "_reg_name_map", reg_name_map)

        # Init _reg_clobber_map. We ensure every register is marked as a
        # clobber of itself before adding the explicit clobbers.
        reg_clobber_map = defaultdict(set)
        for reg in self.regs:
            reg_clobber_map[reg].add(reg)
        for reg_clobber_set in self.reg_clobber_groups:
            for reg in reg_clobber_set:
                reg_clobber_map[reg] |= reg_clobber_set
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

    def expand_regs(self, *regs: RegisterDef | str) -> tuple[RegisterDef, ...]:
        """Expand an input set of registers to include all implicit clobbers.

        .. doctest::

            >>> from int3 import Architectures
            >>> x86_64 = Architectures.x86_64.value
            >>> sorted([reg.name for reg in x86_64.expand_regs("ebx")])
            ['bl', 'bx', 'ebx', 'rbx']

        """
        reg_list: list[RegisterDef] = []
        for reg in regs:
            if isinstance(reg, str):
                reg = self.reg(reg)

            reg_list.append(reg)
            reg_list.extend(self._reg_clobber_map[reg])

        # Using dict.fromkeys to emulate an ordered set.
        return tuple(dict.fromkeys(reg_list))

    def reg(self, name: str) -> RegisterDef:
        """Resolve a register definition by name.

        .. doctest::

            >>> from int3 import Architectures
            >>> x86_64 = Architectures.x86_64.value
            >>> x86_64.reg("rax")
            RegisterDef(name='rax', bit_size=64, llvm_alt_name=None)

        """
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
        """Pack and pad an integer value to a byte length.

        .. doctest::

            >>> from int3 import Architectures
            >>> mips = Architectures.Mips.value
            >>> mips.pad(b"AA", fill_byte=b"B")
            b'BBAA'
            >>> mips.pad(b"AA", width=64, fill_byte=b"C")
            b'CCCCCCAA'

        """
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
        """Pack an integer value into bytes.

        When ``width`` is omitted, the native width of the architecture will be used.

        .. doctest::

            >>> import binascii
            >>> from int3 import Architectures
            >>> mips = Architectures.Mips.value
            >>> binascii.hexlify(mips.pack(0x4141)).decode()
            '00004141'

        """
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
        """Unpack bytes into an integer for this architecture.

        When ``width`` is omitted, the native width of the architecture will be used.

        .. doctest::

            >>> from int3 import Architectures
            >>> mips = Architectures.Mips.value
            >>> hex(mips.unpack(b"AA", width=16))
            '0x4141'

        """

        format_str = self._make_struct_format_str(width=width, signed=signed)
        try:
            return cast(int, struct.unpack(format_str, data)[0])
        except struct.error as e:
            raise Int3InsufficientWidthError(
                f"Unable to unpack {len(data)} bytes using fmt string {format_str}"
            ) from e


class Architectures(Enum):
    """Interface for accessing supported ``Architecture`` definitions.

    .. doctest::

        >>> from int3 import Architectures
        >>> sorted([arch.name for arch in Architectures])
        ['Mips', 'x86', 'x86_64']

    """

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
        keystone_reg_prefix="",
        keystone_arch=KS_ARCH_X86,
        keystone_mode=KS_MODE_32,
        capstone_arch=CS_ARCH_X86,
        capstone_mode=CS_MODE_32,
        reg_cls=Registers.x86,
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
        keystone_reg_prefix="",
        keystone_arch=KS_ARCH_X86,
        keystone_mode=KS_MODE_64,
        capstone_arch=CS_ARCH_X86,
        capstone_mode=CS_MODE_64,
        reg_cls=Registers.x86_64,
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
        keystone_reg_prefix="$",
        keystone_arch=KS_ARCH_MIPS,
        keystone_mode=KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN,
        capstone_arch=CS_ARCH_MIPS,
        capstone_mode=CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN,
        reg_cls=Registers.Mips,
        reg_clobber_groups=tuple(),
    )
    Arm = Architecture(
        name="arm",
        bit_size=32,
        endian=Endian.Little,
        insn_width_flavor=InstructionWidth.Fixed,
        min_insn_width=4,
        toolchain_triple="arm-linux-musleabihf",
        qemu_name="arm",
        linux_kernel_name="armoabi",
        ghidra_name="ARM:LE:32:v7",
        clang_name="armv7",
        llvm_reg_prefix="%",
        keystone_reg_prefix="",
        keystone_arch=KS_ARCH_ARM,
        keystone_mode=KS_MODE_ARM + KS_MODE_LITTLE_ENDIAN,
        capstone_arch=CS_ARCH_ARM,
        capstone_mode=CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN,
        reg_cls=Registers.Arm,
        reg_clobber_groups=(
            {Registers.Arm.r13, Registers.Arm.sp},
            {Registers.Arm.r14, Registers.Arm.lr},
            {Registers.Arm.r15, Registers.Arm.pc},
        ),
    )
    Aarch64 = Architecture(
        name="aarch64",
        bit_size=64,
        endian=Endian.Little,
        insn_width_flavor=InstructionWidth.Fixed,
        min_insn_width=4,
        toolchain_triple="aarch64-linux-musl",
        qemu_name="aarch64",
        linux_kernel_name="arm64",
        ghidra_name="AARCH64:LE:64:default",
        clang_name="aarch64",
        llvm_reg_prefix="%",
        keystone_reg_prefix="",
        keystone_arch=KS_ARCH_ARM64,
        keystone_mode=KS_MODE_LITTLE_ENDIAN,
        capstone_arch=CS_ARCH_ARM64,
        capstone_mode=CS_MODE_LITTLE_ENDIAN,
        reg_cls=Registers.Aarch64,
        reg_clobber_groups=(
            {Registers.Aarch64.x0, Registers.Aarch64.w0},
            {Registers.Aarch64.x1, Registers.Aarch64.w1},
            {Registers.Aarch64.x2, Registers.Aarch64.w2},
            {Registers.Aarch64.x3, Registers.Aarch64.w3},
            {Registers.Aarch64.x4, Registers.Aarch64.w4},
            {Registers.Aarch64.x5, Registers.Aarch64.w5},
            {Registers.Aarch64.x6, Registers.Aarch64.w6},
            {Registers.Aarch64.x7, Registers.Aarch64.w7},
            {Registers.Aarch64.x8, Registers.Aarch64.w8},
            {Registers.Aarch64.x9, Registers.Aarch64.w9},
            {Registers.Aarch64.x10, Registers.Aarch64.w10},
            {Registers.Aarch64.x11, Registers.Aarch64.w11},
            {Registers.Aarch64.x12, Registers.Aarch64.w12},
            {Registers.Aarch64.x13, Registers.Aarch64.w13},
            {Registers.Aarch64.x14, Registers.Aarch64.w14},
            {Registers.Aarch64.x15, Registers.Aarch64.w15},
            {Registers.Aarch64.x16, Registers.Aarch64.w16},
            {Registers.Aarch64.x17, Registers.Aarch64.w17},
            {Registers.Aarch64.x18, Registers.Aarch64.w18},
            {Registers.Aarch64.x19, Registers.Aarch64.w19},
            {Registers.Aarch64.x20, Registers.Aarch64.w20},
            {Registers.Aarch64.x21, Registers.Aarch64.w21},
            {Registers.Aarch64.x22, Registers.Aarch64.w22},
            {Registers.Aarch64.x23, Registers.Aarch64.w23},
            {Registers.Aarch64.x24, Registers.Aarch64.w24},
            {Registers.Aarch64.x25, Registers.Aarch64.w25},
            {Registers.Aarch64.x26, Registers.Aarch64.w26},
            {Registers.Aarch64.x27, Registers.Aarch64.w27},
            {Registers.Aarch64.x28, Registers.Aarch64.w28},
            {Registers.Aarch64.x29, Registers.Aarch64.w29},
            {Registers.Aarch64.x30, Registers.Aarch64.w30, Registers.Aarch64.lr},
        ),
    )

    @staticmethod
    def from_host() -> Architecture:
        """Derive an architecture from the host."""
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
            case "armv6l" | "armv7l" | "armhf":
                return Architectures.from_str("arm")
            case "aarch64" | "arm64":
                return Architectures.from_str("aarch64")
            case _:
                raise Int3MissingEntityError(f"Unrecognized machine {machine}")

    @staticmethod
    def from_str(architecture_name: str) -> Architecture:
        """Derive an architecture from a string name.

        .. doctest::

            >>> from int3 import Architectures
            >>> Architectures.from_str("mips").name
            'mips'

        """
        architecture = _ARCHITECTURE_MAP.get(architecture_name, None)
        if architecture is None:
            raise Int3MissingEntityError(f"No such architecture {architecture_name}")

        return architecture

    @staticmethod
    def names() -> list[str]:
        """Retrieve the names of all supported architectures."""
        return list(_ARCHITECTURE_MAP.keys())


_ARCHITECTURE_MAP: dict[str, Architecture] = {
    architecture_enum.value.name: architecture_enum.value
    for architecture_enum in Architectures
}
