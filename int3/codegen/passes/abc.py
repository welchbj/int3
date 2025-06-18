from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from capstone import CsInsn
from capstone.mips_const import MIPS_OP_IMM, MIPS_OP_REG
from capstone.x86_const import X86_OP_IMM, X86_OP_REG

from int3.architecture import Architecture, Architectures

from ..code_generator import CodeGenerator

if TYPE_CHECKING:
    from ..compiled_segment import CompiledSegment


class SegmentMutationPass(ABC):
    @abstractmethod
    def mutate_segment(self, segment: "CompiledSegment") -> "CompiledSegment":
        """Apply a mutation to an input segment, producing a new output segment."""


@dataclass(frozen=True)
class InstructionMutationPass(ABC):
    segment: "CompiledSegment"
    bad_bytes: bytes
    codegen: CodeGenerator = field(init=False)

    def __post_init__(self):
        object.__setattr__(self, "codegen", CodeGenerator(self.arch))

    @property
    def arch(self) -> Architecture:
        return self.segment.arch

    @abstractmethod
    def mutate_instruction(self, insn: CsInsn) -> bytes:
        """Apply a mutation to an input instruction, producing new raw instruction(s).

        The returned sequence of bytes must correspond to instructions that are functionallity-
        equivalent to the input instruction. Returned sequences of bytes may include bad bytes,
        but will be ignored by the mutation engine.

        """

    def is_dirty(self, data: bytes) -> bool:
        return any(b in data for b in self.bad_bytes)

    def is_mov_insn(self, insn: CsInsn) -> bool:
        # XXX: This is kind of a lazy approach that might be inaccurate.
        mnemonic: str = insn.mnemonic
        return mnemonic.startswith("mov")

    def is_reg_imm_insn(self, insn: CsInsn) -> bool:
        if len(insn.operands) != 2:
            return False

        match self.arch:
            case Architectures.x86_64.value | Architectures.x86.value:
                return bool(
                    insn.operands[0].type == X86_OP_REG
                    and insn.operands[1].type == X86_OP_IMM
                )
            case Architectures.Mips.value:
                return bool(
                    insn.operands[0].type == MIPS_OP_REG
                    and insn.operands[1].type == MIPS_OP_IMM
                )
            case _:
                raise NotImplementedError(f"Not yet supported: {self.arch.name}")
