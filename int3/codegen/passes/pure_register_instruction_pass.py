from int3.errors import Int3UnsuitableCodeMutation
from int3.instructions import Instruction

from .abc import InstructionMutationPass


class PureRegisterInstructionPass(InstructionMutationPass):
    """Mutate "pure register" instructions.

    A "pure register" instruction is one that has only register operands.

    """

    def should_mutate(self, insn: Instruction) -> bool:
        return len(insn.operands) >= 2 and insn.has_only_register_operands()

    def mutate(self, insn: Instruction) -> tuple[Instruction, ...]:
        """Apply register substitution mutation strategies."""

        # TODO

        raise Int3UnsuitableCodeMutation(f"{self.__class__.__name__} not implemented")
