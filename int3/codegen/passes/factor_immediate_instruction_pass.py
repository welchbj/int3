from dataclasses import replace

from int3.errors import Int3CodeGenerationError
from int3.factor import ImmediateMutationContext
from int3.instructions import Instruction

from .abc import InstructionMutationPass


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

        imm_ctx = ImmediateMutationContext(
            arch=self.arch,
            bad_bytes=self.bad_bytes,
            imm=imm,
            dest=reg,
            scratch_regs=scratch_regs,
            insn=insn,
        )

        # If the goal is to "simply" load an immediate into a register, then we
        # can lean directly on the codegen API.
        if insn.is_mov():
            return self._put_insns(imm_ctx)

        # Otherwise, we need to put a value into an intermediary scratch register,
        # and then replace the immediate in the original instruction with the scratch
        # register.
        candidate_insn_sequences = []
        for scratch_reg in scratch_regs:
            modified_scratch_regs = set(scratch_regs) - {scratch_reg}

            # We "reserve" our intermediate register (selected from the available
            # scratch registers). We then move into the sub-problem of putting the
            # desired immediate value into this selected intermediate register,
            # which we'll then in turn move into our actual goal destination register.
            mutated_imm_ctx = replace(
                imm_ctx, dest=scratch_reg, scratch_regs=tuple(modified_scratch_regs)
            )
            put_insns = self._put_insns(mutated_imm_ctx)
            new_insns = *put_insns, insn.operands.replace(-1, scratch_reg)
            candidate_insn_sequences.append(new_insns)

        def _insn_tuple_len(insns: tuple[Instruction, ...]) -> int:
            return sum(len(insn.raw) for insn in insns)

        return min(candidate_insn_sequences, key=_insn_tuple_len)

    def _put_insns(self, ctx: ImmediateMutationContext) -> tuple[Instruction, ...]:
        raw_candidates: list[bytes] = []

        for scratch_reg in ctx.scratch_regs:
            try:
                gadgets = self.codegen.hl_put(
                    ctx.with_locked_reg(scratch_reg), scratch_reg
                )
                raw_candidate = b"".join(gadget.bytes for gadget in gadgets)
                raw_candidates.append(raw_candidate)
            except Int3CodeGenerationError:
                # This scratch register didn't work; try the next one.
                continue

        if not raw_candidates:
            raise Int3CodeGenerationError(
                f"Unable to generate clean code to load {ctx.imm:#x} into {ctx.dest} "
                f"with any available scratch register"
            )

        return self.choose(raw_candidates)
