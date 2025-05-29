from __future__ import annotations

import random
import string
from dataclasses import dataclass, field

from int3.errors import (
    Int3ExhaustedEntropyError,
    Int3MissingEntityError,
)
from int3.ir import IrVariable


@dataclass
class Scope:
    var_map: dict[str, IrVariable] = field(init=False, default_factory=dict)
    reserved_names: set[str] = field(init=False, default_factory=set)

    def allocate_var_name(self, prefix: str = "") -> str:
        """Make and reserve a unique variable name for this scope."""
        if prefix:
            prefix = f"{prefix}_"

        for i in range(100):
            suffix = "".join(random.choice(string.hexdigits) for _ in range(4))

            name = f"{prefix}{suffix}"
            if name in self.var_map.keys() or name in self.reserved_names:
                continue

            self.reserved_names.add(name)
            return name
        else:
            raise Int3ExhaustedEntropyError(
                f"Unable to generate unique variable name after {i} tries"
            )

    def add_var(self, var: IrVariable):
        """Register an IR variable in this scope."""
        self.var_map[var.name] = var
        self.reserved_names.remove(var.name)

    def resolve_var(self, name: str) -> IrVariable:
        """Resolve a name into an IR variable within this scope."""
        var = self.var_map.get(name, None)
        if var is None:
            raise Int3MissingEntityError(f"Unable to resolve variable with name {name}")

        return var
