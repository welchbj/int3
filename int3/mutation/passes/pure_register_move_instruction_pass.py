import logging

from int3.codegen import Choice, Instruction

from .abc import InstructionMutationPass

logger = logging.getLogger(__name__)


class PureRegisterMoveInstructionPass(InstructionMutationPass):
    """Mutate pure register-to-register move instruction."""

    def should_mutate(self, insn: Instruction) -> bool:
        return insn.has_only_register_operands() and insn.is_mov()

    def mutate(self, insn: Instruction) -> Choice:
        dest_reg = insn.operands.reg(0)
        src_reg = insn.operands.reg(1)
        return self.codegen.ll_put(dest_reg, src_reg)
