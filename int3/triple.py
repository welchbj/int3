from __future__ import annotations

from dataclasses import dataclass

from int3.architecture import Architecture, Architectures
from int3.platform import Platform


@dataclass(frozen=True)
class Triple:
    """Encapsulation of an LLVM target machine triple.

    Triple strings have the form:

        <arch><sub>-<vendor>-<sys>-<env>

    See:
        https://mcyoung.xyz/2025/04/14/target-triples/
        https://clang.llvm.org/docs/CrossCompilation.html#target-triple

    """

    arch: str
    vendor: str
    sys: str
    env: str

    sub: str = ""

    def __str__(self) -> str:
        return f"{self.arch}{self.sub}-{self.vendor}-{self.sys}-{self.env}"

    @staticmethod
    def from_arch_and_platform(arch: Architecture, platform: Platform) -> Triple:
        arch_str = arch.clang_name
        platform_str = platform.name.lower()

        return Triple(
            arch=arch_str,
            vendor="pc",
            sys=platform_str,
            env="unknown",
        )
