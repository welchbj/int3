from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from int3.ir.variables import IrGlobalVar, IrLocalVar

if TYPE_CHECKING:
    from .compiler import Compiler


@dataclass
class CompilerScope:
    cc: "Compiler"

    local_vars: list[IrLocalVar]
    global_vars: list[IrGlobalVar]

    # TODO: Optimize resolving variables by name?

    def clone(self) -> CompilerScope:
        # We intentionally keep the actual var objects the same underlying Python
        # objects.
        return CompilerScope(
            cc=self.cc,
            local_vars=list(self.local_vars),
            global_vars=list(self.global_vars),
        )
