from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Iterable

from int3.architecture import Architecture
from int3.codegen import CodeGenerator, Instruction, Segment


@dataclass(frozen=True)
class InstructionMutationPass(ABC):
    segment: Segment
    bad_bytes: bytes
    codegen: CodeGenerator = field(init=False)

    def __post_init__(self):
        object.__setattr__(self, "codegen", CodeGenerator(self.arch))

    @property
    def arch(self) -> Architecture:
        return self.segment.arch

    def is_dirty(self, data: bytes) -> bool:
        """Return whether the byte sequence contains bad bytes."""
        return any(b in data for b in self.bad_bytes)

    def to_instructions(self, data: bytes) -> tuple[Instruction, ...]:
        """Convert a byte sequence to Instruction instances."""
        return Instruction.from_bytes(data, self.segment.triple)

    def choose(self, seq: Iterable[bytes]) -> tuple[Instruction, ...]:
        """Choose the shortest clean candidate byte sequence."""
        chosen_code = min(
            iter(data for data in seq if not self.is_dirty(data)), key=len
        )
        return self.to_instructions(chosen_code)

    @abstractmethod
    def should_mutate(self, insn: Instruction) -> bool:
        """Determine whether a mutation should fire."""

    @abstractmethod
    def mutate(self, insn: Instruction) -> tuple[Instruction, ...]:
        """Apply a mutation to an input instruction, producing equivalent instruction(s).

        Returned sequences of instructions may include bad bytes, but will be skipped by
        the mutation engine.

        """
