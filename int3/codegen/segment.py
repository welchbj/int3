from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from int3.architecture import Architecture, RegisterDef
from int3.assembly import assemble, disassemble

from .instruction import Instruction

if TYPE_CHECKING:
    from int3.platform import Triple


@dataclass(frozen=True)
class Segment:
    """A segment of instructions aware of potential side effects.

    TODO: doctest

    """

    triple: "Triple"
    raw_asm: bytes

    insns: tuple[Instruction, ...] = field(init=False)
    tainted_regs: set[RegisterDef] = field(init=False)
    scratch_regs: set[RegisterDef] = field(init=False)

    def __post_init__(self):
        all_insns = tuple(
            Instruction(cs_insn=cs_insn, triple=self.triple)
            for cs_insn in disassemble(self.arch, self.raw_asm)
        )

        object.__setattr__(self, "insns", all_insns)
        object.__setattr__(self, "tainted_regs", self._init_tainted_regs())
        object.__setattr__(self, "scratch_regs", self._init_scratch_regs())

    @staticmethod
    def from_asm(triple: "Triple", asm: str) -> Segment:
        """Factory method to create an instance from raw machine code."""
        assembled_asm = assemble(arch=triple.arch, assembly=asm)
        return Segment(triple=triple, raw_asm=assembled_asm)

    @property
    def arch(self) -> Architecture:
        return self.triple.arch

    @property
    def raw(self) -> bytes:
        """Raw machine code for this segment."""
        return b"".join(insn.raw for insn in self.insns)

    def __bytes__(self) -> bytes:
        return self.raw

    def _init_tainted_regs(self) -> set[RegisterDef]:
        tainted_regs = set()
        for insn in self.insns:
            tainted_regs |= insn.tainted_regs
        return tainted_regs

    def _init_scratch_regs(self) -> set[RegisterDef]:
        return set(
            reg
            for reg in self.triple.call_preserved_regs
            if reg not in self.tainted_regs
            and reg not in self.arch.expanded_reserved_regs
        )

    def dirty_instructions(self, bad_bytes: bytes) -> tuple[Instruction, ...]:
        """The violating instructions within this segment for a set of bad bytes."""
        return tuple(insn for insn in self.insns if insn.is_dirty(bad_bytes))

    def is_clean(self, bad_bytes: bytes) -> bool:
        """Whether this segment doesn't contain bad bytes."""
        return len(self.dirty_instructions(bad_bytes)) == 0

    def scratch_regs_for_size(self, bit_size: int) -> tuple[RegisterDef, ...]:
        """Find candidate scratch registers for a given bit width."""
        return tuple(reg for reg in self.scratch_regs if reg.bit_size == bit_size)
