from dataclasses import dataclass

from int3.registers import Registers, x86_64Registers, x86Registers

from .semantic_emitter import SemanticEmitter
from .x86_64emitter import x86_64Emitter
from .x86_emitter import x86Emitter


@dataclass
class LinuxEmitter(SemanticEmitter[Registers]):
    """An emitter for Linux targets (generic with respect to architecture)."""

    # TODO: Support for the various syscall arguments.
    def syscall(self, num: int):
        raise NotImplementedError("syscall() not yet implemented")


class Linuxx86Emitter(x86Emitter, LinuxEmitter[x86Registers]):
    ...


class Linuxx86_64Emitter(x86_64Emitter, LinuxEmitter[x86_64Registers]):
    ...
