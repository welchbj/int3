from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from int3.architecture import Architecture
from int3.codegen import Choice, CodeGenerator, Instruction, Segment

if TYPE_CHECKING:
    from int3.platform import Triple


@dataclass(frozen=True)
class InstructionMutationPass(ABC):
    segment: Segment
    # XXX: Should bad_bytes be a member?
    bad_bytes: bytes
    codegen: CodeGenerator = field(init=False)

    def __post_init__(self):
        object.__setattr__(self, "codegen", CodeGenerator(self.triple))

    @property
    def arch(self) -> Architecture:
        return self.segment.arch

    @property
    def triple(self) -> "Triple":
        return self.segment.triple

    def is_dirty(self, data: bytes) -> bool:
        """Return whether the byte sequence contains bad bytes."""
        return any(b in data for b in self.bad_bytes)

    @abstractmethod
    def should_mutate(self, insn: Instruction) -> bool:
        """Determine whether a mutation should fire."""

    @abstractmethod
    def mutate(self, insn: Instruction) -> Choice:
        """Apply a mutation to an input instruction, producing equivalent instruction(s).

        Pass mutation implementations do not need to filter out presented options with bad
        bytes - these will be pruned by the mutation engine.

        """
