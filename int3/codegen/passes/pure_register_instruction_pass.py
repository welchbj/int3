from int3.errors import Int3UnsuitableCodeMutation
from int3.instructions import Instruction

from .abc import InstructionMutationPass


class PureRegisterInstructionPass(InstructionMutationPass):
    """Mutate "pure register" instructions.

    A "pure register" instruction is one that has only register operands.

    """

    def should_mutate(self, insn: Instruction) -> bool:
        return len(insn.operands) >= 2 and insn.has_only_register_operands()

    def mutate(self, insn: Instruction) -> tuple[Instruction, ...]:
        """Apply register substitution mutation strategies."""

        # For each register used in the operation, we try replacing it with a transitory
        # register (which we call the "shadow" register).
        for reg_to_mutate_idx in range(len(insn.operands)):
            reg_to_mutate = insn.operands.reg(reg_to_mutate_idx)
            for shadow_reg in self.segment.scratch_regs_for_size(
                reg_to_mutate.bit_size
            ):
                for put_seq in self.codegen.ll_put(dest=shadow_reg, src=reg_to_mutate):
                    new_code = b""
                    new_code += b"".join(p.bytes for p in put_seq)
                    new_code += insn.operands.replace(reg_to_mutate_idx, shadow_reg).raw

                    # XXX
                    triple = self.segment.triple
                    print(Instruction.summary(insn)[0])
                    print("-" * 20)
                    insns = Instruction.from_bytes(new_code, triple)
                    print("\n".join(Instruction.summary(*insns)))
                    print("=" * 20)

                    if self.is_dirty(new_code):
                        continue

                    # Return the first valid sequence.
                    return self.to_instructions(new_code)
        else:
            raise Int3UnsuitableCodeMutation(
                f"{self.__class__.__name__} unable to find appropriate substitution"
            )
