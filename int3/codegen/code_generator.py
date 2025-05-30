from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from int3.compilation import FlattenedFunction, FlattenedProgram


logger = logging.getLogger(__name__)


@dataclass
class CodeGenerator:
    program: "FlattenedProgram"

    def emit_asm(self) -> bytes:
        # TODO
        return b"TODO"

    def _process_func(self, func: "FlattenedFunction"):
        # Iterate over the log of LLIR operations, determining the candidate
        # gadgets for each LLIR operation. This lets us define the "register holes"
        # we have for this function, and setup an appropriate SMT problem to solver for.
        # TODO
        pass
