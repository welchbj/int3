import logging

from int3.codegen import Choice, Instruction
from int3.errors import Int3CodeGenerationError
from int3.factor import FactorContext, FactorOperation, compute_factor

from .abc import InstructionMutationPass

logger = logging.getLogger(__name__)


class FactorInplaceImmediateInstructionPass(InstructionMutationPass):
    """Factor an inplace immediate by breaking up commutative operations.

    For example, the following Mips instruction:

    .. code-block:: nasm

        addiu $at, $at, 0x100

    Could be broken up into:

    .. code-block:: nasm

        addi $at, $at, -0xf80
        addi $at, $at, 0x1080

    """

    def should_mutate(self, insn: Instruction) -> bool:
        return (
            len(insn.operands) >= 2
            and insn.operands.is_reg(0)
            and insn.operands.is_reg(1)
            and insn.operands.reg(0) == insn.operands.reg(1)
            and insn.operands.is_imm(-1)
            and insn.operands.imm(-1) <= 2 ** (insn.arch.bit_size // 2)
            and (insn.is_add() or insn.is_sub() or insn.is_xor())
        )

    def mutate(self, insn: Instruction) -> Choice:
        """Factor immediate values into multiple instructions."""
        dest_reg = insn.operands.reg(0)
        imm = insn.operands.imm(-1)

        # TODO
        width = min(dest_reg.bit_size, self.arch.bit_size // 2)

        # Instead of computing the full factor solve, we set our target to be the
        # immediate itself, so we can reconstruct the immediate's effect via equivalent
        # successive operations with different immediates.

        allowed_ops: tuple[FactorOperation, ...]
        if insn.is_add() or insn.is_sub():
            allowed_ops = (
                FactorOperation.Add,
                FactorOperation.Sub,
            )
        elif insn.is_xor():
            allowed_ops = (FactorOperation.Xor,)
        else:
            raise Int3CodeGenerationError(f"Invalid instruction type: {insn}")

        result = compute_factor(
            FactorContext(
                arch=self.arch,
                target=imm,
                start=0,
                bad_bytes=self.bad_bytes,
                min_depth=2,
                max_depth=5,
                width=width,
                allowed_ops=allowed_ops,
                allow_bad_bytes_in_start=True,
            )
        )

        def _to_signed(value: int) -> int:
            if value & (1 << (width - 1)):
                return value - (1 << width)
            else:
                return value

        # Process each factor op (aside from the leading Init) into instruction choices.
        ops = []
        for clause in result.clauses[1:]:
            operand = _to_signed(clause.operand)

            if clause.operation == FactorOperation.Add:
                ops.append(self.codegen.add(dest_reg, operand))
            elif clause.operation == FactorOperation.Sub:
                ops.append(self.codegen.sub(dest_reg, operand))
            elif clause.operation == FactorOperation.Xor:
                ops.append(self.codegen.xor(dest_reg, operand))
            else:
                raise Int3CodeGenerationError(
                    f"Unexpected factor operation: {clause.operation}"
                )

        return self.codegen.choice(self.codegen.segment(*ops))
