from int3.codegen import Choice, Instruction

from .abc import InstructionMutationPass


class NopRewriterInstructionPass(InstructionMutationPass):
    """Replace literal nop instructions with functional nops."""

    def should_mutate(self, insn: Instruction) -> bool:
        return insn.is_nop()

    def mutate(self, insn: Instruction) -> Choice:
        scratch_regs = self.segment.scratch_regs_for_size(self.arch.bit_size)

        options: list[Choice] = []
        for scratch_reg in scratch_regs:
            options.append(
                self.codegen.choice(
                    self.codegen.add(scratch_reg, scratch_reg),
                    self.codegen.mov(scratch_reg, scratch_reg),
                    self.codegen.sub(scratch_reg, scratch_reg),
                    self.codegen.xor(scratch_reg, scratch_reg),
                    self.codegen.inc(scratch_reg),
                )
            )

        return self.codegen.choice(*options)
