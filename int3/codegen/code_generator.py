from dataclasses import dataclass
from typing import TYPE_CHECKING

from int3.ir import IrBranch, IrOperation

from .gadget import Gadget
from .implication import Implication, ImmediateImplication, RegisterImplication

if TYPE_CHECKING:
    from int3.compilation import Block, Function


@dataclass
class CodeGenerator:
    bad_bytes: bytes
    gadgets: list[Gadget]

    def emit_asm(self, function: list["Function"]) -> bytes:
        # Process blocks into a half-compiled form. We hold off on finalizing
        # branches, jumps, and calls, as we might be able to re-arrange them
        # to avoid bad byte constraints.
        # TODO

        # Re-arrange blocks to avoid bad bytes in relocations.
        # TODO

        # Stitch it all together.
        # TODO

        return b"TODO"

    def _map_variables(self, block: "Block"): ...

    def _translate_ir_operation(self, operation: IrBranch | IrOperation): ...
