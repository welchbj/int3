from __future__ import annotations

import logging
import textwrap
from dataclasses import dataclass, field

from int3.architecture import Architecture, Architectures, RegisterDef
from int3.assembly import assemble
from int3.errors import Int3CodeGenerationError

type RegType = RegisterDef | str
type ImmType = int


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AsmGadget:
    text: str
    bytes: bytes
    len: int = field(init=False)

    def __post_init__(self):
        unindented_text = "\n".join(
            line.strip()
            for line in textwrap.dedent(self.text).splitlines()
            if line.strip()
        )
        logger.debug("Created gadget for the following assembly:")
        for line in textwrap.indent(unindented_text, prefix="    ").splitlines():
            logger.debug(line)

        object.__setattr__(self, "text", unindented_text)
        object.__setattr__(self, "len", len(self.bytes))

    def __str__(self) -> str:
        return self.text


@dataclass(frozen=True)
class CodeGenerator:
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

    def syscall(self, value: ImmType | None = None) -> AsmGadget:
        if value is None:
            return self.gadget("syscall")
        else:
            return self.gadget(f"syscall {value:#x}")

    def breakpoint(self) -> AsmGadget:
        match self.arch:
            case Architectures.x86_64.value | Architectures.x86.value:
                return self.gadget("int3")
            case Architectures.Mips.value:
                return self.gadget("break")
            case _:
                raise NotImplementedError(f"Unhandled architecture: {self.arch.name}")

    def inc(self, reg: RegType) -> AsmGadget:
        match self.arch:
            case Architectures.x86_64.value | Architectures.x86.value:
                return self.gadget(f"inc {reg}")
            case Architectures.Mips.value:
                return self.gadget(f"addi ${reg}, 0x1")
            case _:
                raise NotImplementedError(f"Unhandled architecture: {self.arch.name}")

    def xor(self, one: RegType, two: ImmType | RegType) -> AsmGadget:
        return self.gadget(f"xor {one}, {two}")

    def add(self, one: RegType, two: ImmType | RegType) -> AsmGadget:
        return self.gadget(f"add {one}, {two}")

    def sub(self, one: RegType, two: ImmType | RegType) -> AsmGadget:
        return self.gadget(f"sub {one}, {two}")

    def mov(self, one: RegType, two: ImmType | RegType) -> AsmGadget:
        match self.arch:
            case Architectures.x86_64.value | Architectures.x86.value:
                return self.gadget(f"mov {one}, {two}")
            case Architectures.Mips.value:
                if isinstance(two, int):
                    return self.gadget(f"li ${one}, {two:#x}")
                else:
                    return self.gadget(f"move ${one}, {two}")
            case _:
                raise NotImplementedError(f"Unhandled architecture: {self.arch.name}")

    def compute_pc(self, result: RegType) -> AsmGadget:
        """Compute the program counter for the instruction following this gadget."""
        match self.arch:
            case Architectures.x86_64.value:
                return self.gadget(f"lea {result}, [rip]")
            case Architectures.Mips.value:
                raise Int3CodeGenerationError(
                    "Mips does not support fine-grained PC-relative addressing"
                )
            case _:
                raise NotImplementedError(f"Unhandled architecture: {self.arch.name}")

    def jump(self, value: ImmType | RegType) -> AsmGadget:
        match self.arch:
            case Architectures.x86.value:
                return self.gadget(f"jmp {value}")
            case Architectures.x86_64.value:
                # See: https://www.felixcloutier.com/x86/jmp
                return self.gadget(f"jmp {value}")
            case Architectures.Mips.value:
                if isinstance(value, int):
                    return self.gadget(f"j {value:#x}")
                else:
                    return self.gadget(f"jr {value}")
            case _:
                raise NotImplementedError(f"Unhandled architecture: {self.arch.name}")
