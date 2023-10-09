from dataclasses import dataclass

from int3.registers import Registers, x86_64Registers, x86Registers

from ..architectures.x86_64emitter import x86_64Emitter
from ..architectures.x86_emitter import x86Emitter
from ..semantic_emitter import SemanticEmitter


@dataclass
class WindowsEmitter(SemanticEmitter[Registers]):
    """An emitter for Windows targets (generic with respect to 32- vs 64-bit)."""

    # TODO: Additional Windows-specific functionality (like function hash comparisons).


class Windowsx86Emitter(x86Emitter, WindowsEmitter[x86Registers]):
    ...


class Windowsx86_64Emitter(x86_64Emitter, WindowsEmitter[x86_64Registers]):
    ...
