from typing import Iterable

from int3.architecture import RegisterDef
from int3.errors import Int3UnsuitableCodeMutation, Int3CodeGenerationError
from int3.instructions import Instruction

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

        raise Int3UnsuitableCodeMutation(f"Immediate {imm:#x} is too large")


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
        syscall_bit_size = self.segment.arch.syscall_imm_bit_size

        # Round up to the nearest power-of-2 width (8, 16, 32, 64)
        width = next(w for w in (8, 16, 32, 64) if syscall_bit_size <= w)

        imm = self.segment.make_clean_imm(bit_size=width)

        # Mask to the actual syscall width to ensure we don't exceed it
        mask = (1 << syscall_bit_size) - 1
        imm = imm & mask

        raw_asm = self.codegen.syscall(imm).bytes
        return self.to_instructions(raw_asm)


class FactorImmediateInstructionPass(InstructionMutationPass):
    """Reconstruct an immediate operand across factored operations."""

    def should_mutate(self, insn: Instruction) -> bool:
        """Mutate instructions that have reg and imm operands."""
        return (
            len(insn.operands) >= 2
            and insn.operands.is_reg(0)
            and insn.operands.is_imm(-1)
        )

    def mutate(self, insn: Instruction) -> tuple[Instruction, ...]:
        """Factor immediate values into multiple instructions."""
        reg = insn.operands.reg(0)
        imm = insn.operands.imm(-1)
        scratch_regs = tuple(self.segment.scratch_regs_for_size(reg.bit_size))

        # If the goal is to "simply" load an immediate into a register, then we
        # can lean directly on the codegen API.
        if insn.is_mov():
            return self._put_insns(dest=reg, imm=imm, scratch_regs=scratch_regs)

        # Otherwise, we need to put a value into an intermediary scratch register,
        # and then replace the immediate in the original instruction with the scratch
        # register.
        candidate_insn_sequences = []
        for scratch_reg in scratch_regs:
            modified_scratch_regs = set(scratch_regs) - {scratch_reg}
            put_insns = self._put_insns(
                dest=scratch_reg, imm=imm, scratch_regs=modified_scratch_regs
            )

            new_insns = *put_insns, insn.operands.replace(-1, scratch_reg)
            candidate_insn_sequences.append(new_insns)

        def _insn_tuple_len(insns: tuple[Instruction, ...]) -> int:
            return sum(len(insn.raw) for insn in insns)

        return min(candidate_insn_sequences, key=_insn_tuple_len)

    def _put_insns(
        self, dest: RegisterDef, imm: int, scratch_regs: Iterable[RegisterDef]
    ) -> tuple[Instruction, ...]:
        raw_candidates: list[bytes] = []

        for scratch_reg in scratch_regs:
            try:
                gadgets = self.codegen.hl_put(
                    dest=dest,
                    value=imm,
                    scratch=scratch_reg,
                    bad_bytes=self.bad_bytes,
                )
                raw_candidate = b"".join(gadget.bytes for gadget in gadgets)
                raw_candidates.append(raw_candidate)
            except Int3CodeGenerationError:
                # This scratch register didn't work; try the next one.
                continue

        if not raw_candidates:
            raise Int3CodeGenerationError(
                f"Unable to generate clean code to load {imm:#x} into {dest} "
                f"with any available scratch register"
            )

        return self.choose(raw_candidates)
