from __future__ import annotations

import random
import string
from dataclasses import dataclass, field

from int3.errors import (
    Int3ExhaustedEntropyError,
    Int3IrAlreadyNamedError,
    Int3MissingEntityError,
)
from int3.ir import VAR_UNNAMED, IrVariable


@dataclass
class Scope:
    var_map: dict[str, IrVariable] = field(init=False, default_factory=dict)

    def _make_var_name(self, prefix: str = "") -> str:
        """Make a unique variable name for this scope."""
        if prefix:
            prefix = f"{prefix}_"

        for i in range(100):
            suffix = "".join(random.choice(string.ascii_lowercase) for _ in range(4))

            name = f"{prefix}{suffix}"
            if name in self.var_map.keys():
                continue

            return name
        else:
            raise Int3ExhaustedEntropyError(
                f"Unable to generate unique variable name after {i} tries"
            )

    def add_var(self, var: IrVariable) -> str:
        """Register an IR variable in this scope, assigning (and returning) a name for it."""
        if var.name != VAR_UNNAMED:
            raise Int3IrAlreadyNamedError(f"Variable already has name: {var.name}")

        var_name = self._make_var_name(prefix=str(var))
        self.var_map[var_name] = var
        var.name = var_name
        return var_name

    def resolve_var(self, name: str) -> IrVariable:
        """Resolve a name into an IR variable within this scope."""
        var = self.var_map.get(name, None)
        if var is None:
            raise Int3MissingEntityError(f"Unable to resolve variable with name {name}")

        return var
