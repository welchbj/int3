from dataclasses import dataclass, field

from capstone import CsInsn

from int3.architecture import Architecture, RegisterDef
from int3.assembly import disassemble


@dataclass(frozen=True)
class CompiledSegment:
    arch: Architecture
    raw_asm: bytes
    bad_bytes: bytes

    all_instructions: tuple[CsInsn, ...] = field(init=False)
    dirty_instructions: tuple[CsInsn, ...] = field(init=False)
    scratch_regs: set[RegisterDef] = field(init=False)

    def __post_init__(self):
        all_insns = disassemble(self.arch, self.raw_asm)
        dirty_insns = tuple(
            insn for insn in all_insns if any(b in insn.bytes for b in self.bad_bytes)
        )

        object.__setattr__(self, "all_instructions", all_insns)
        object.__setattr__(self, "dirty_instructions", dirty_insns)

        # TODO: Find all call_clobbered registers that are not the result of any
        #       assembly operation.
        object.__setattr__(self, "scratch_regs", tuple())

    @property
    def is_clean(self) -> bool:
        return len(self.dirty_instructions) == 0

    @property
    def program(self) -> bytes:
        return b"".join(insn.bytes for insn in self.all_instructions)

    def __bytes__(self) -> bytes:
        return self.program
