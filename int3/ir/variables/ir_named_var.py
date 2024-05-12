from dataclasses import dataclass

from .ir_var import IrVar


@dataclass
class IrNamedVar(IrVar):
    name: str
