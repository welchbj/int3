from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from int3.architecture import Architecture

from ..code_generator import CodeGenerator
from ..instruction import Instruction

if TYPE_CHECKING:
    from ..compiled_segment import CompiledSegment


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

    def is_dirty(self, data: bytes) -> bool:
        return any(b in data for b in self.bad_bytes)

    def to_instructions(self, data: bytes) -> tuple[Instruction, ...]:
        return Instruction.from_bytes(data, self.segment.triple)

    @abstractmethod
    def should_mutate(self, insn: Instruction) -> bool:
        """Determine whether a mutation should fire."""

    @abstractmethod
    def mutate(self, insn: Instruction) -> tuple[Instruction, ...]:
        """Apply a mutation to an input instruction, producing equivalent instruction(s).

        Returned sequences of instructions may include bad bytes, but will be skipped by
        the mutation engine.

        """
