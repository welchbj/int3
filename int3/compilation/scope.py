from __future__ import annotations

import random
import string
from dataclasses import dataclass, field

from int3.errors import Int3ExhaustedEntropyError
from int3.ir import Variable


@dataclass
class Scope:
    var_map: dict[str, Variable] = field(default_factory=dict)

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

    def resolve_var(self, name: str) -> Variable: ...
