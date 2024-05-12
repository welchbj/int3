from dataclasses import dataclass

from .ir_named_var import IrNamedVar


@dataclass
class IrGlobalVar(IrNamedVar):
    pass
