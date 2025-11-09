from int3.codegen import Instruction

from .abc import InstructionMutationPass


class AddSyscallOperandInstructionPass(InstructionMutationPass):
    """Add an operand to a syscall instruction.

    For example, the naked syscall instruction on Mips assembles to
    0000000c, containing null bytes. The addition of an immediate operand
    encodes the immediate in place of these null bytes.

    """

    def should_mutate(self, insn: Instruction) -> bool:
        """Mutate syscall instructions."""
        return insn.is_syscall()

    def mutate(self, insn: Instruction) -> tuple[Instruction, ...]:
        """Replace the syscall immediate operand."""
        arch = self.segment.arch
        syscall_bit_size = arch.syscall_imm_bit_size

        # Round up to the nearest power-of-2 width (8, 16, 32, 64)
        width = next(w for w in (8, 16, 32, 64) if syscall_bit_size <= w)
        imm = arch.make_clean_imm(bad_bytes=self.bad_bytes, bit_size=width)

        # Mask to the actual syscall width to ensure we don't exceed it
        mask = (1 << syscall_bit_size) - 1
        imm = imm & mask

        raw_asm = self.codegen.syscall(imm).bytes
        return self.to_instructions(raw_asm)
