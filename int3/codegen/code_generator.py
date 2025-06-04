from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from int3.architecture import Architecture, Architectures, RegisterDef
from int3.assembly import assemble

if TYPE_CHECKING:
    from int3.compilation import Compiler


@dataclass(frozen=True)
class AsmGadget:
    text: str
    bytes: bytes

    def __str__(self) -> str:
        return self.text


@dataclass
class CodeGenerator:
    # XXX: Knowledge of bad bytes?

    arch: "Architecture"

    def gadget(self, asm: str) -> AsmGadget:
        return AsmGadget(text=asm, bytes=self.assemble(asm))

    def assemble(self, asm: str) -> bytes:
        return assemble(self.arch, asm)

    def syscall(self) -> AsmGadget:
        # XXX: Arch-specific code
        return self.gadget("syscall")

    def breakpoint(self) -> AsmGadget:
        # XXX: Arch-specific code
        return self.gadget("int3")

    def jump(self, value: int | RegisterDef) -> AsmGadget:
        match self.arch:
            case Architectures.x86.value:
                return self.gadget(f"jmp {value}")
            case Architectures.x86_64.value:
                return self.gadget(f"jmp {value}")
            case Architectures.Mips.value:
                if isinstance(value, int):
                    return self.gadget(f"j {value}")
                else:
                    return self.gadget(f"jr {value}")
            case _:
                raise NotImplementedError(f"Unhandled architecture: {self.arch}")
