from __future__ import annotations

from dataclasses import dataclass, field

from int3.architecture import Architecture, RegisterDef
from int3.assembly import assemble, disassemble
from int3.platform import Triple

from .instruction import Instruction


@dataclass(frozen=True)
class CompiledSegment:
    triple: Triple
    raw_asm: bytes
    bad_bytes: bytes

    instructions: tuple[Instruction, ...] = field(init=False)
    dirty_instructions: tuple[Instruction, ...] = field(init=False)
    tainted_regs: set[RegisterDef] = field(init=False)
    scratch_regs: set[RegisterDef] = field(init=False)

    def __post_init__(self):
        all_insns = tuple(
            Instruction(cs_insn=cs_insn, triple=self.triple)
            for cs_insn in disassemble(self.arch, self.raw_asm)
        )
        dirty_insns = tuple(insn for insn in all_insns if insn.is_dirty(self.bad_bytes))

        object.__setattr__(self, "instructions", all_insns)
        object.__setattr__(self, "dirty_instructions", dirty_insns)
        object.__setattr__(self, "tainted_regs", self._init_tainted_regs())
        object.__setattr__(self, "scratch_regs", self._init_scratch_regs())

    @staticmethod
    def from_asm(triple: Triple, asm: str, bad_bytes: bytes = b"") -> CompiledSegment:
        assembled_asm = assemble(arch=triple.arch, assembly=asm)
        return CompiledSegment(
            triple=triple, raw_asm=assembled_asm, bad_bytes=bad_bytes
        )

    @property
    def arch(self) -> Architecture:
        return self.triple.arch

    @property
    def is_clean(self) -> bool:
        return len(self.dirty_instructions) == 0

    @property
    def raw(self) -> bytes:
        return b"".join(insn.raw for insn in self.instructions)

    def __bytes__(self) -> bytes:
        return self.raw

    def _init_tainted_regs(self) -> set[RegisterDef]:
        tainted_regs = set()
        for insn in self.instructions:
            tainted_regs |= insn.tainted_regs
        return tainted_regs

    def _init_scratch_regs(self) -> set[RegisterDef]:
        return set(
            reg
            for reg in self.triple.call_preserved_regs
            if reg not in self.tainted_regs
        )

    def scratch_reg_for_size(self, bit_size: int) -> RegisterDef:
        return next(reg for reg in self.scratch_regs if reg.bit_size == bit_size)
