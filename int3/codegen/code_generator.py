from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from int3.architecture import Architecture
    from int3.compilation import Compiler


@dataclass
class CodeGenerator:
    compiler: "Compiler"

    @property
    def arch(self) -> "Architecture":
        return self.compiler.arch

    def syscall(self) -> str:
        # XXX: Arch-specific code
        return "syscall"

    def breakpoint(self) -> str:
        # XXX: Arch-specific code
        return "int3"
