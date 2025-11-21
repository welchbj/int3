from int3.architecture import Architectures
from int3.codegen import Choice, Instruction

from .abc import InstructionMutationPass


class Aarch64MovkInstructionPass(InstructionMutationPass):
    """Mutate aarch64 movk instructions to use BFI with a scratch register.

    The movk instruction inserts a 16-bit immediate into a specific position
    of a register while preserving other bits. When the immediate is small,
    movk often encodes with null bytes.

    This pass replaces movk like:

    .. code-block:: nasm

        movk rd, #imm, lsl #shift

    With an equivalent BFI sequence:

    .. code-block:: nasm

        ; <load imm into scratch>
        bfi rd, scratch, #shift, #16

    """

    def should_mutate(self, insn: Instruction) -> bool:
        return self.arch.name == "aarch64" and insn.mnemonic == "movk"

    def mutate(self, insn: Instruction) -> Choice:
        dest_reg = insn.operands.reg(0)
        imm = insn.operands.imm(1)
        shift = insn.cs_insn.operands[1].shift.value

        scratch_regs = self.segment.scratch_regs_for_size(dest_reg.bit_size)

        options = []
        for scratch in scratch_regs:
            options.append(
                self.codegen.segment(
                    self.codegen.ll_put(scratch, imm),
                    self.codegen.inline("bfi", dest_reg, scratch, shift, 16),
                )
            )

        return self.codegen.choice(*options)
