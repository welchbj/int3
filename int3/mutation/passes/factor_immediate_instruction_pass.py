import logging
from dataclasses import replace

from int3.codegen import Choice, FluidSegment, Instruction
from int3.errors import Int3CodeGenerationError
from int3.factor import ImmediateMutationContext

from .abc import InstructionMutationPass

logger = logging.getLogger(__name__)


class FactorImmediateInstructionPass(InstructionMutationPass):
    """Reconstruct an immediate operand across factored operations."""

    def should_mutate(self, insn: Instruction) -> bool:
        """Mutate instructions that have reg and imm operands."""
        return (
            len(insn.operands) >= 2
            and insn.operands.is_reg(0)
            and insn.operands.is_imm(-1)
        )

    def mutate(self, insn: Instruction) -> Choice:
        """Factor immediate values into multiple instructions."""
        dest_reg = insn.operands.reg(0)
        imm = insn.operands.imm(-1)
        scratch_regs = self.segment.scratch_regs_for_size(dest_reg.bit_size)

        options = []

        # For mov instructions, we can use hl_put_imm fairly directly.
        if insn.is_mov():
            return self.codegen.hl_put_imm(
                imm=imm,
                dest=dest_reg,
                scratch_regs=scratch_regs,
                bad_bytes=self.bad_bytes,
            )

        # Otherwise, we need to put a value into an intermediary scratch register,
        # and then replace the immediate in the original instruction with the scratch
        # register.
        for scratch_reg in scratch_regs:
            remaining_scratch_regs = tuple(r for r in scratch_regs if r != scratch_reg)
            if not remaining_scratch_regs:
                continue

            # We "reserve" our intermediate register (selected from the available
            # scratch registers). We then move into the sub-problem of putting the
            # desired immediate value into this selected intermediate register,
            # which we'll then in turn move into our actual goal destination register.
            options.append(
                self.codegen.segment(
                    self.codegen.hl_put_imm(
                        imm=imm,
                        dest=scratch_reg,
                        scratch_regs=remaining_scratch_regs,
                        bad_bytes=self.bad_bytes,
                    ),
                    insn.operands.replace(-1, scratch_reg),
                )
            )

        return self.codegen.choice(*options)
