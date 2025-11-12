from __future__ import annotations

from dataclasses import dataclass, field

from int3.architecture import (
    Architecture,
    Architectures,
    RegisterDef,
    Registers,
)
from int3.architecture.architecture import _ARCHITECTURE_ALIAS_MAP
from int3.codegen import Instruction, Segment
from int3.errors import Int3ArgumentError, Int3CodeGenerationError

from .platform import Platform
from .syscall_convention import SyscallConvention


@dataclass(frozen=True)
class Triple:
    """Encapsulation of an LLVM target machine triple.

    Triple strings typically have the form:

        ``<arch><sub>-<vendor>-<sys>-<env>``

    See:
        * https://mcyoung.xyz/2025/04/14/target-triples/
        * https://clang.llvm.org/docs/CrossCompilation.html#target-triple

    """

    arch: Architecture
    platform: Platform

    arch_str: str = field(init=False)
    vendor_str: str = field(init=False)
    sys_str: str = field(init=False)
    env_str: str = field(init=False)
    sub_str: str = field(init=False, default_factory=str)

    call_preserved_regs: tuple[RegisterDef, ...] = field(init=False)
    call_clobbered_regs: tuple[RegisterDef, ...] = field(init=False)
    syscall_convention: SyscallConvention = field(init=False)

    def __post_init__(self):
        arch_str = self.arch.clang_name
        platform_str = self.platform.name.lower()

        object.__setattr__(self, "arch_str", arch_str)
        object.__setattr__(self, "vendor_str", "pc")
        object.__setattr__(self, "sys_str", platform_str)
        object.__setattr__(self, "env_str", "unknown")

        object.__setattr__(
            self, "call_preserved_regs", self._resolve_call_preserved_regs()
        )
        object.__setattr__(
            self, "call_clobbered_regs", self._resolve_call_clobbered_regs()
        )
        object.__setattr__(
            self, "syscall_convention", self._resolve_syscall_convention()
        )

    def __str__(self) -> str:
        return f"{self.arch_str}{self.sub_str}-{self.vendor_str}-{self.sys_str}-{self.env_str}"

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} [{self}]>"

    def _resolve_call_preserved_regs(self) -> tuple[RegisterDef, ...]:
        """Determine which registers LLVM considers call-preserved for this platform/architecture.

        See:
            Callee saved vs preserved: https://stackoverflow.com/a/16265609
            LLVM-specific callee-saved discussion: https://stackoverflow.com/a/64611401

        """
        match self.platform, self.arch:
            case Platform.Linux, Architectures.x86.value:
                # See: https://github.com/llvm/llvm-project/blob/release/15.x/llvm/lib/Target/X86/X86CallingConv.td#L1128
                return self.arch.expand_regs(
                    Registers.x86.esi,
                    Registers.x86.edi,
                    Registers.x86.ebx,
                    Registers.x86.ebp,
                )
            case Platform.Linux, Architectures.x86_64.value:
                # See: https://github.com/llvm/llvm-project/blob/release/15.x/llvm/lib/Target/X86/X86CallingConv.td#L1129
                return self.arch.expand_regs(
                    Registers.x86_64.rbx,
                    Registers.x86_64.r12,
                    Registers.x86_64.r13,
                    Registers.x86_64.r14,
                    Registers.x86_64.r15,
                    Registers.x86_64.rbp,
                )
            case Platform.Linux, Architectures.Mips.value:
                # See: https://github.com/llvm/llvm-project/blob/release/15.x/llvm/lib/Target/Mips/MipsCallingConv.td#L370
                return self.arch.expand_regs(
                    Registers.Mips.ra,
                    Registers.Mips.fp,
                    Registers.Mips.s0,
                    Registers.Mips.s1,
                    Registers.Mips.s2,
                    Registers.Mips.s3,
                    Registers.Mips.s4,
                    Registers.Mips.s5,
                    Registers.Mips.s6,
                    Registers.Mips.s7,
                )
            case Platform.Linux, Architectures.Arm.value:
                # See: https://github.com/llvm/llvm-project/blob/release/15.x/llvm/lib/Target/ARM/ARMCallingConv.td#L270
                return self.arch.expand_regs(
                    Registers.Arm.r4,
                    Registers.Arm.r5,
                    Registers.Arm.r6,
                    Registers.Arm.r7,
                    Registers.Arm.r8,
                    Registers.Arm.r9,
                    Registers.Arm.r10,
                    Registers.Arm.r11,
                    Registers.Arm.sp,
                    Registers.Arm.lr,
                )
            case Platform.Linux, Architectures.Aarch64.value:
                # See: https://github.com/llvm/llvm-project/blob/release/15.x/llvm/lib/Target/AArch64/AArch64CallingConvention.td#L362
                return self.arch.expand_regs(
                    Registers.Aarch64.x19,
                    Registers.Aarch64.x20,
                    Registers.Aarch64.x21,
                    Registers.Aarch64.x22,
                    Registers.Aarch64.x23,
                    Registers.Aarch64.x24,
                    Registers.Aarch64.x25,
                    Registers.Aarch64.x26,
                    Registers.Aarch64.x27,
                    Registers.Aarch64.x28,
                    Registers.Aarch64.x29,
                    Registers.Aarch64.x30,
                    Registers.Aarch64.sp,
                )
            case _:
                raise NotImplementedError(
                    f"Unsupported combination: {self.platform.name}, {self.arch.name}"
                )

    def _resolve_call_clobbered_regs(self) -> tuple[RegisterDef, ...]:
        """Derive call-clobbered registers, based on LLVM's call-preserved register definition."""
        return tuple(
            reg for reg in self.arch.regs if reg not in self.call_preserved_regs
        )

    def _resolve_syscall_convention(self) -> SyscallConvention:
        """Derive the syscall calling convention for this triple.

        See:
            https://man7.org/linux/man-pages/man2/syscall.2.html

        """
        if self.platform == Platform.Linux:
            syscall_conv: SyscallConvention
            match self.arch:
                case Architectures.x86.value:
                    syscall_conv = SyscallConvention(
                        arch=self.arch,
                        sys_num=Registers.x86.eax,
                        result=Registers.x86.eax,
                        args=(
                            Registers.x86.ebx,
                            Registers.x86.ecx,
                            Registers.x86.edx,
                            Registers.x86.esi,
                            Registers.x86.edi,
                            Registers.x86.ebp,
                        ),
                    )
                case Architectures.x86_64.value:
                    syscall_conv = SyscallConvention(
                        arch=self.arch,
                        sys_num=Registers.x86_64.rax,
                        result=Registers.x86_64.rax,
                        args=(
                            Registers.x86_64.rdi,
                            Registers.x86_64.rsi,
                            Registers.x86_64.rdx,
                            Registers.x86_64.r10,
                            Registers.x86_64.r8,
                            Registers.x86_64.r9,
                        ),
                    )
                case Architectures.Mips.value:
                    syscall_conv = SyscallConvention(
                        arch=self.arch,
                        sys_num=Registers.Mips.v0,
                        result=Registers.Mips.v0,
                        args=(
                            Registers.Mips.a0,
                            Registers.Mips.a1,
                            Registers.Mips.a2,
                            Registers.Mips.a3,
                            # XXX: How to pass additional arguments on the stack?
                        ),
                    )
                case Architectures.Arm.value:
                    syscall_conv = SyscallConvention(
                        arch=self.arch,
                        sys_num=Registers.Arm.r7,
                        result=Registers.Arm.r0,
                        args=(
                            Registers.Arm.r0,
                            Registers.Arm.r1,
                            Registers.Arm.r2,
                            Registers.Arm.r3,
                            Registers.Arm.r4,
                            Registers.Arm.r5,
                        ),
                    )
                case Architectures.Aarch64.value:
                    syscall_conv = SyscallConvention(
                        arch=self.arch,
                        sys_num=Registers.Aarch64.x8,
                        result=Registers.Aarch64.x0,
                        args=(
                            Registers.Aarch64.x0,
                            Registers.Aarch64.x1,
                            Registers.Aarch64.x2,
                            Registers.Aarch64.x3,
                            Registers.Aarch64.x4,
                            Registers.Aarch64.x5,
                        ),
                    )

            return syscall_conv
        else:
            raise NotImplementedError(
                "Non-Linux Syscall convention resolution not yet implemented"
            )

    def insns(self, *raw_insns: str | bytes) -> tuple[Instruction, ...]:
        """Transform assembly or machine code into a sequence of instructions."""
        parsed_insns: list[Instruction] = []
        for raw_insn in raw_insns:
            if isinstance(raw_insn, str):
                new_insns = Instruction.from_str(raw_insn, triple=self)
            else:
                new_insns = Instruction.from_bytes(raw_insn, triple=self)

            parsed_insns.extend(new_insns)

        return tuple(parsed_insns)

    def segment(self, *raw_insns: str | bytes) -> Segment:
        """Transform assembly or machine code into a segment."""
        return Segment.from_insns(self, *self.insns(*raw_insns))

    def one_insn_or_raise(self, raw: str | bytes) -> Instruction:
        """Transform assembly or machine code into exactly one instruction."""
        insns = self.insns(raw)
        if len(insns) != 1:
            raise Int3CodeGenerationError(
                f"Expected one insruction but generated {len(insns)}"
            )

        return insns[0]

    @staticmethod
    def from_host() -> Triple:
        """Derive a triple from the host system."""
        return Triple(arch=Architectures.from_host(), platform=Platform.from_host())

    @staticmethod
    def from_str(triple_str: str) -> Triple:
        """Parse a triple from its string representation.

        Supports LLVM-style triple strings with 2-4 components:

        - ``<arch>-<sys>``
        - ``<arch>-<sys>-<env>``
        - ``<arch>-<vendor>-<sys>-<env>``

        .. doctest::

            >>> from int3 import Triple
            >>> triple = Triple.from_str("x86_64-linux")
            >>> triple.arch.name
            'x86_64'
            >>> triple.platform.name
            'Linux'

        """
        parts = triple_str.split("-")
        if len(parts) < 2 or len(parts) > 4:
            raise Int3ArgumentError(
                f"Triple string must have 2-4 components, got {len(parts)}: {triple_str}"
            )

        # Parse architecture from first component.
        arch_str = parts[0]
        arch = _parse_arch_from_triple_component(arch_str)

        # Parse platform from system component. The system component is at
        # different positions depending on the overall component count:
        # - 2 parts: arch-sys
        # - 3 parts: arch-sys-env OR arch-vendor-sys (we assume arch-sys-env)
        # - 4 parts: arch-vendor-sys-env
        if len(parts) == 2:
            sys_str = parts[1]
        elif len(parts) == 3:
            # Assume format is arch-sys-env (more common than arch-vendor-sys)
            sys_str = parts[1]
        else:  # len(parts) == 4
            sys_str = parts[2]
        platform = _parse_platform_from_triple_component(sys_str)

        return Triple(arch=arch, platform=platform)


def _parse_arch_from_triple_component(arch_str: str) -> Architecture:
    """Parse an architecture from a triple component string."""
    arch = _ARCHITECTURE_ALIAS_MAP.get(arch_str.lower())
    if arch is None:
        supported = sorted(set(_ARCHITECTURE_ALIAS_MAP.keys()))
        raise Int3ArgumentError(
            f"Unrecognized architecture in triple: {arch_str}. "
            f"Supported: {', '.join(supported)}"
        )

    return arch


def _parse_platform_from_triple_component(sys_str: str) -> Platform:
    """Parse a platform from a triple system component string."""
    sys_str_lower = sys_str.lower()

    if sys_str_lower.startswith("linux") or sys_str_lower in ("gnu", "musl"):
        return Platform.Linux
    elif sys_str_lower in ("windows", "win32", "mingw32", "mingw64", "msvc"):
        return Platform.Windows
    else:
        raise Int3ArgumentError(f"Unrecognized system in triple: {sys_str}")
