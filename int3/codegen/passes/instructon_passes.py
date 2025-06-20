from typing import Iterator, cast

from int3.architecture import RegisterDef
from int3.errors import Int3UnsuitableCodeMutation, Int3WrappedKeystoneError
from int3.factor import (
    FactorClause,
    FactorContext,
    FactorOperation,
    FactorResult,
    compute_factor,
)

from ..instruction import Instruction
from .abc import InstructionMutationPass


class MoveSmallImmediateInstructionPass(InstructionMutationPass):
    def should_mutate(self, insn: Instruction) -> bool:
        return insn.is_mov() and insn.operands.is_reg(0) and insn.operands.is_imm(1)

    def mutate(self, insn: Instruction) -> tuple[Instruction, ...]:
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


class MoveFactorImmediateInstructionPass(InstructionMutationPass):
    def should_mutate(self, insn: Instruction) -> bool:
        return insn.is_mov() and insn.operands.is_reg(0) and insn.operands.is_imm(1)

    def mutate(self, insn: Instruction) -> tuple[Instruction, ...]:
        reg = insn.operands.reg(0)
        imm = insn.operands.imm(1)
        factor_result = self._factor_to_imm(imm, width=reg.bit_size)

        code = b""
        for clause in factor_result.clauses:
            asm_candidates = list(self._factor_clause_to_asm(clause, reg))
            if not asm_candidates:
                raise Int3UnsuitableCodeMutation(
                    "Unable to generate any factor clauses"
                )

            filtered_asm_candidates = [
                candidate
                for candidate in asm_candidates
                if not self.is_dirty(candidate)
            ]
            if not filtered_asm_candidates:
                raise Int3UnsuitableCodeMutation(
                    "Unable to generate clean factor clauses"
                )

            # Choose the shortest of the available candidates.
            new_code = min(asm_candidates, key=len)
            code += new_code

        return self.to_instructions(code)

    def _factor_to_imm(self, imm: int, width: int) -> FactorResult:
        allow_overflow = width == self.arch.bit_size
        factor_ctx = FactorContext(
            arch=self.arch,
            target=imm,
            bad_bytes=self.bad_bytes,
            allow_overflow=allow_overflow,
            width=width,
        )
        return compute_factor(factor_ctx)

    # TODO: We can split up clear gadgets

    def _mov_instructions(self, reg: RegisterDef, imm: int) -> Iterator[bytes]:
        yield self.codegen.mov(reg, imm).bytes

        try:
            yield self.codegen.xor(reg, reg).bytes + self.codegen.add(reg, imm).bytes
        except Int3WrappedKeystoneError:
            pass

        # TODO: Others

    def _factor_clause_to_asm(
        self, clause: FactorClause, reg: RegisterDef
    ) -> Iterator[bytes]:
        scratch_reg = self.segment.scratch_reg_for_size(reg.bit_size)
        imm = clause.operand

        match clause.operation:
            case FactorOperation.Init:
                yield from self._mov_instructions(reg, imm)
            case FactorOperation.Sub:
                try:
                    yield self.codegen.sub(reg, imm).bytes
                except Int3WrappedKeystoneError:
                    pass

                for mov_insn in self._mov_instructions(scratch_reg, imm):
                    yield mov_insn + self.codegen.sub(reg, scratch_reg).bytes
            case FactorOperation.Add:
                try:
                    yield self.codegen.add(reg, imm).bytes
                except Int3WrappedKeystoneError:
                    pass

                for mov_insn in self._mov_instructions(scratch_reg, imm):
                    yield mov_insn + self.codegen.add(reg, scratch_reg).bytes
            case FactorOperation.Xor:
                try:
                    yield self.codegen.xor(reg, imm).bytes
                except Int3WrappedKeystoneError:
                    pass

                for mov_insn in self._mov_instructions(scratch_reg, imm):
                    yield mov_insn + self.codegen.xor(reg, scratch_reg).bytes
            case FactorOperation.Neg:
                raise NotImplementedError("Negation support not yet implemented")
