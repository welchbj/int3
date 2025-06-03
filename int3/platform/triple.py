from __future__ import annotations

from dataclasses import dataclass, field

from int3.architecture import Architecture, Architectures, Registers

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

    def __post_init__(self):
        arch_str = self.arch.clang_name
        platform_str = self.platform.name.lower()

        object.__setattr__(self, "arch_str", arch_str)
        object.__setattr__(self, "vendor_str", "pc")
        object.__setattr__(self, "sys_str", platform_str)
        object.__setattr__(self, "env_str", "unknown")

    def __str__(self) -> str:
        return f"{self.arch_str}{self.sub_str}-{self.vendor_str}-{self.sys_str}-{self.env_str}"

    def resolve_syscall_convention(self) -> SyscallConvention:
        """Derive the syscall calling convention for this triple.

        See:
            https://man7.org/linux/man-pages/man2/syscall.2.html

        """
        if self.platform == Platform.Linux:
            match self.arch:
                case Architectures.x86.value:
                    return SyscallConvention(
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
                    return SyscallConvention(
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
                    return SyscallConvention(
                        sys_num=Registers.Mips.v0,
                        result=Registers.Mips.v0,
                        args=(
                            Registers.Mips.a0,
                            Registers.Mips.a1,
                            Registers.Mips.a2,
                            Registers.Mips.a3,
                            # TODO: How do pass additinal arguments on the stack?
                        ),
                    )
        else:
            raise NotImplementedError(
                "Non-Linux Syscall convention resolution not yet implemented"
            )
