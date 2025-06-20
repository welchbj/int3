from __future__ import annotations

from dataclasses import dataclass, field

from int3.architecture import Architecture, Architectures, RegisterDef, Registers

from .platform import Platform
from .syscall_convention import SyscallConvention


@dataclass(frozen=True)
class Triple:
    """Encapsulation of an LLVM target machine triple.

    Triple strings have the form:

        <arch><sub>-<vendor>-<sys>-<env>

    See:
        https://mcyoung.xyz/2025/04/14/target-triples/
        https://clang.llvm.org/docs/CrossCompilation.html#target-triple

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
                            # XXX: How do pass additinal arguments on the stack?
                        ),
                    )

            return syscall_conv
        else:
            raise NotImplementedError(
                "Non-Linux Syscall convention resolution not yet implemented"
            )
