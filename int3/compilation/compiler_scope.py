from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from int3.ir.variables import IrGlobalVar, IrLocalVar

if TYPE_CHECKING:
    from .compiler import Compiler


@dataclass
class CompilerScope:
    cc: "Compiler"

    local_vars: list[IrLocalVar] = field(default_factory=list)
    global_vars: list[IrGlobalVar] = field(default_factory=list)

    # TODO: Optimize resolving variables by name?

    def clone(
        self, inherit_locals: bool = True, inherit_globals: bool = True
    ) -> CompilerScope:
        # We intentionally keep the actual var objects the same underlying Python
        # objects.
        local_vars = list(self.local_vars) if inherit_locals else []
        global_vars = list(self.global_vars) if inherit_globals else []

        return CompilerScope(cc=self.cc, local_vars=local_vars, global_vars=global_vars)
