from dataclasses import dataclass
from typing import Generic

from int3.gadget import Gadget
from int3.registers import (
    Registers,
    x86_64Registers,
    x86Registers,
)

from .semantic_emitter import SemanticEmitter
from .x86_emitter import x86Emitter
from .x86_64emitter import x86_64Emitter


@dataclass
class WindowsEmitter(SemanticEmitter[Registers], Generic[Registers]):
    """An emitter for Windows targets (generic with respect to 32- vs 64-bit)."""

    # TODO


class Windowsx86Emitter(x86Emitter, WindowsEmitter[x86Registers]):
    ...


class Windowsx86_64Emitter(x86_64Emitter, WindowsEmitter[x86_64Registers]):
    ...
