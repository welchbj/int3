from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from int3.compilation import FlattenedProgram


logger = logging.getLogger(__name__)


@dataclass
class CodeGenerator:
    program: "FlattenedProgram"

    def emit_asm(self) -> bytes:
        # TODO
        return b"TODO"
