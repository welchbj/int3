from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from int3.architecture import Architecture, Architectures, RegisterDef
from int3.assembly import assemble


@dataclass(frozen=True)
class AsmGadget:
    text: str
    bytes: bytes
    len: int = field(init=False)

    def __post_init__(self):
        object.__setattr__(self, "len", len(self.bytes))

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

    def nop_pad(self, pad_len: int) -> bytes:
        nop_bytes = self.gadget("nop").bytes
        if pad_len % len(nop_bytes):
            # TODO
            1 / 0

        num_repeats = pad_len // len(nop_bytes)
        return nop_bytes * num_repeats

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
                # See: https://www.felixcloutier.com/x86/jmp
                return self.gadget(f"jmp {value}")
            case Architectures.Mips.value:
                if isinstance(value, int):
                    return self.gadget(f"j {value}")
                else:
                    return self.gadget(f"jr {value}")
            case _:
                raise NotImplementedError(f"Unhandled architecture: {self.arch}")
