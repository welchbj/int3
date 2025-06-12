from typing import cast

from capstone import CsInsn

from .abc import InstructionMutationPass


class MoveSmallImmediateInstructionPass(InstructionMutationPass):
    def mutate_instruction(self, insn: CsInsn) -> bytes:
        if not self.is_mov_insn(insn) or not self.is_reg_imm_insn(insn):
            # Not an applicable instruction.
            return b""

        reg = cast(str, insn.reg_name(insn.operands[0].value.reg))
        imm = cast(int, insn.operands[1].value.imm)
        if imm <= 0x10:
            # TODO: We should be able to test different gadgets for the presence
            #       of bad bytes. For example, we could have other ways of
            #       clearing the register other an XOR.
            code = self.codegen.xor(reg, reg).bytes
            code += self.codegen.inc(reg).bytes * imm
            return code
        else:
            return b""
