from dataclasses import dataclass
from typing import Generic

from int3.registers import (
    Registers,
    x86_64Registers,
    x86Registers,
)

from .architecture_emitter import ArchitectureEmitter
from .x86_emitter import x86Emitter
from .x86_64emitter import x86_64Emitter


@dataclass
class WindowsEmitter(ArchitectureEmitter[Registers], Generic[Registers]):
    """An emitter for Windows targets (generic with respect to 32- vs 64-bit)."""

    def resolve_dll(self, name: str, dst: Registers | None = None) -> Registers:
        # TODO
        print("resolve_dll called!")
        return self.pop()


class Windowsx86Emitter(x86Emitter, WindowsEmitter[x86Registers]):
    ...


class Windowsx86_64Emitter(x86_64Emitter, WindowsEmitter[x86_64Registers]):
    ...
