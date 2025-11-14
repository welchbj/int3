from int3.codegen import Choice, Instruction

from .abc import InstructionMutationPass


class LoadUpperImmediateInstructionPass(InstructionMutationPass):
    """Replace load-upper-immediate instructions that have dirty bytes."""

    def should_mutate(self, insn: Instruction) -> bool:
        """Mutate lui (load upper immediate) instructions."""
        # XXX: Add support for other architectures with lui-style instructions.
        return (
            self.arch.name == "mips"
            and self.arch.bit_size == 32
            and insn.mnemonic == "lui"
        )

    def mutate(self, insn: Instruction) -> Choice:
        dest_reg = insn.operands.reg(0)
        imm = insn.operands.imm(1)
        scratch_regs = self.segment.scratch_regs_for_size(dest_reg.bit_size)

        # On 32-bit mips, lui loads the immediate into the upper 16 bits (imm << 16)
        # and clears the lower 16 bits.
        actual_value = imm << 16
        return self.codegen.hl_put_imm(
            imm=actual_value,
            dest=dest_reg,
            scratch_regs=scratch_regs,
            bad_bytes=self.bad_bytes,
        )
