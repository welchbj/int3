from int3.codegen import Choice, Instruction

from .abc import InstructionMutationPass


class MipsReturnInstructionPass(InstructionMutationPass):
    """Mutate a mips ``jr $ra`` instruction to a ``jalr`` variant."""

    def should_mutate(self, insn: Instruction) -> bool:
        return self.arch.name == "mips" and insn.asm_str == "jr $ra"

    def mutate(self, insn: Instruction) -> Choice:
        ra_reg = self.arch.reg("ra")
        scratch_regs = self.segment.scratch_regs_for_size(ra_reg.bit_size)

        options: list[Instruction] = []
        for scratch_reg in scratch_regs:
            # The assembler adds a trailing nop as the branch delay slot, which we
            # strip off by only taking the first instruction.
            jalr_insn = (
                self.codegen.inline("jalr", scratch_reg, ra_reg).choose().insns[0]
            )
            options.append(jalr_insn)

        return self.codegen.choice(*options)
