from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from int3.architecture import Architecture
from int3.ir import IrBranch, IrOperation

from .gadget import Gadget
from .implication import ImmediateImplication, Implication, RegisterImplication

if TYPE_CHECKING:
    from int3.compilation import Block, Compiler, Function


logger = logging.getLogger(__name__)


@dataclass
class CodeGenerator:
    compiler: "Compiler"

    # TODO: Probably need some kind of GadgetCollection concept
    # gadgets: list[Gadget]

    def emit_asm(self) -> bytes:
        # XXX: Can we translate the functions into a sequence of gadgets with
        #      "register holes"? We can then leverage gadget implications to
        #      ascertain the set of allowable registers.
        #
        #      So we compile our IR into a lower level variant of the IR, which
        #      acts on a sequence of infinite registers (this is also a suitable
        #      abstraction for the bytes data type). We then keep some registers
        #      "in reserve" for when we eclipse the number of registers available
        #      for the arch, to be used in stack-referencing helpers.
        #
        #      We are still going to have to keep track of scope somehow in order
        #      to know when we can re-use certain registers. Can we "split" virtual
        #      registers once they're eligible for re-use? Should we add a pseudo
        #      instruction to "kill" a virtual register when it goes out of scope?
        #
        #      We should also cleanup the compiler/block/function semantics around
        #      variable name / label generation and the semantics around variables
        #      vs constants.

        for func_name, func in self.compiler.func.func_map.items():
            logger.debug(f"Creating candidate compilation for {func_name}...")
            # XXX

        return b"TODO"
