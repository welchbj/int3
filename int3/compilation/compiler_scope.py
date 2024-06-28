from __future__ import annotations

import random
import string
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from int3.errors import Int3ExhaustedEntropyError
from int3.ir.variables import IrGlobalVar, IrLocalVar

if TYPE_CHECKING:
    from .compiler import Compiler


@dataclass
class CompilerScope:
    cc: "Compiler"

    local_vars: list[IrLocalVar] = field(default_factory=list)
    global_vars: list[IrGlobalVar] = field(default_factory=list)

    used_var_names: set[str] = field(init=False, default_factory=set)

    # TODO: Optimize resolving variables by name?

    def make_var_name(self, prefix: str = "") -> str:
        """Make a unique variable name for this scope."""
        if prefix:
            prefix = f"{prefix}_"

        for i in range(100):
            suffix = "".join(random.choice(string.ascii_lowercase) for _ in range(4))

            name = f"{prefix}{suffix}"
            if name in self.used_var_names:
                continue

            self.used_var_names.add(name)
            return name
        else:
            raise Int3ExhaustedEntropyError(
                f"Unable to generate unique variable name after {i} tries"
            )

    def clone(
        self, inherit_locals: bool = True, inherit_globals: bool = True
    ) -> CompilerScope:
        # We intentionally keep the actual var objects the same underlying Python
        # objects.
        local_vars = list(self.local_vars) if inherit_locals else []
        global_vars = list(self.global_vars) if inherit_globals else []

        return CompilerScope(cc=self.cc, local_vars=local_vars, global_vars=global_vars)
