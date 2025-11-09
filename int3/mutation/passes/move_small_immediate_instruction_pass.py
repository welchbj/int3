from int3.codegen import Instruction
from int3.errors import Int3UnsuitableCodeMutation

from .abc import InstructionMutationPass


class MoveSmallImmediateInstructionPass(InstructionMutationPass):
    """Mutate small immediates into a series of increments."""

    def should_mutate(self, insn: Instruction) -> bool:
        """Mutate instructions with small immediate values."""
        return (
            insn.is_mov()
            and len(insn.operands) >= 2
            and insn.operands.is_reg(0)
            and insn.operands.is_imm(-1)
        )

    def mutate(self, insn: Instruction) -> tuple[Instruction, ...]:
        """Convert immediate values into a series of increments."""
        reg = insn.operands.reg(0)
        imm = insn.operands.imm(1)

        if imm <= 0x10:
            # XXX: We should be able to test different gadgets for the presence
            #      of bad bytes. For example, we could have other ways of
            #      clearing the register other than an XOR.
            code = self.codegen.xor(reg, reg).bytes
            code += self.codegen.inc(reg).bytes * imm
            return self.to_instructions(code)
        else:
            raise Int3UnsuitableCodeMutation(f"Immediate {imm:#x} is too large")
