from dataclasses import dataclass

from .ir_var import IrVar


@dataclass
class IrNamedVar(IrVar):
    name: str

    def __str__(self) -> str:
        return f"var/{self.name}:{self.type_}"
