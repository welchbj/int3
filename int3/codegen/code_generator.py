from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from int3.architecture import Architecture
    from int3.compilation import Compiler
    from int3.platform import SyscallConvention


@dataclass
class CodeGenerator:
    compiler: "Compiler"

    @property
    def arch(self) -> "Architecture":
        return self.compiler.arch

    # TODO
