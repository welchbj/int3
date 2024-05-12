from dataclasses import dataclass

from .ir_named_var import IrNamedVar


@dataclass
class IrLocalVar(IrNamedVar):
    pass
