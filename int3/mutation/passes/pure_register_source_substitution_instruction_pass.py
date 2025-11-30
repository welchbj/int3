import logging

from int3.codegen import Choice, Instruction

from .abc import InstructionMutationPass

logger = logging.getLogger(__name__)


class PureRegisterSourceSubstitutionInstructionPass(InstructionMutationPass):
    """Mutate pure register instructions by substituting source register operands.

    This pass handles instructions that have only register operands (no immediates
    or memory operands) but still contain bad bytes due to how specific register
    numbers are encoded in the instruction format.

    For example, on aarch64, ``blr x8`` encodes as ``00013fd6`` which contains a
    null byte. By substituting x8 with x9, we get:

    .. code-block:: nasm

        mov x9, x8  ; e90308aa (clean)
        blr x9      ; 20013fd6 (clean)

    The pass only substitutes source registers, never destination registers, to
    preserve instruction semantics.

    """

    def should_mutate(self, insn: Instruction) -> bool:
        return any(insn.operands.is_reg(i) for i in range(len(insn.operands)))

    def mutate(self, insn: Instruction) -> Choice:
        options = []
        for i in range(len(insn.operands)):
            if not insn.operands.is_reg(i):
                continue

            orig_reg = insn.operands.reg(i)

            # Only substitute source (read) registers, not destinations.
            if orig_reg not in insn.regs_read:
                continue

            # If we are interacting with a register list, we make sure we don't include
            # duplicate registers in a mutated register list.
            if insn.operands.is_reg_list(i):
                skip_regs = set(insn.operands.reg_list(i))
            else:
                skip_regs = set()

            for scratch_reg in self.segment.scratch_regs_for_size(orig_reg.bit_size):
                if scratch_reg == orig_reg:
                    continue
                elif scratch_reg in skip_regs:
                    # Avoid duplicate registers in register lists.
                    continue

                new_insn = insn.operands.replace(i, scratch_reg)
                segment = self.codegen.segment(
                    self.codegen.ll_put(scratch_reg, orig_reg),
                    new_insn,
                )
                options.append(segment)

        return self.codegen.choice(*options)
