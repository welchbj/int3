from typing import Iterator, cast

from capstone import CsInsn

from int3.errors import Int3WrappedKeystoneError
from int3.factor import (
    FactorClause,
    FactorContext,
    FactorOperation,
    FactorResult,
    compute_factor,
)

from .abc import InstructionMutationPass


class MoveSmallImmediateInstructionPass(InstructionMutationPass):
    def mutate_instruction(self, insn: CsInsn) -> bytes:
        if not self.is_mov_insn(insn) or not self.is_reg_imm_insn(insn):
            # Not an applicable instruction.
            return b""

        reg = cast(str, insn.reg_name(insn.operands[0].value.reg))
        imm = cast(int, insn.operands[1].value.imm)
        if imm <= 0x10:
            # TODO: We should be able to test different gadgets for the presence
            #       of bad bytes. For example, we could have other ways of
            #       clearing the register other than an XOR.
            code = self.codegen.xor(reg, reg).bytes
            code += self.codegen.inc(reg).bytes * imm
            return code
        else:
            return b""


class MoveFactorImmediateInstructionPass(InstructionMutationPass):
    def mutate_instruction(self, insn: CsInsn) -> bytes:
        if not self.is_mov_insn(insn) or not self.is_reg_imm_insn(insn):
            # Not an applicable instruction.
            return b""

        reg_bit_size = cast(int, insn.operands[0].size) * 8
        imm = cast(int, insn.operands[1].value.imm)
        reg = cast(str, insn.reg_name(insn.operands[0].value.reg))
        factor_result = self._factor_to_imm(imm, width=reg_bit_size)

        code = b""
        for clause in factor_result.clauses:
            asm_candidates = [
                asm_candidate
                for asm_candidate in self._factor_clause_to_asm(
                    clause, reg, reg_bit_size
                )
                if not self.is_dirty(asm_candidate)
            ]
            if not asm_candidates:
                # Unable to encode this clause into instruction(s).
                return b""

            # Choose the shortest code block.
            new_code = min(asm_candidates, key=len)
            code += new_code

        return code

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

    def _mov_instructions(self, reg: str, imm: int) -> Iterator[bytes]:
        yield self.codegen.mov(reg, imm).bytes

        try:
            yield self.codegen.xor(reg, reg).bytes + self.codegen.add(reg, imm).bytes
        except Int3WrappedKeystoneError:
            pass

        # TODO: Others

    def _factor_clause_to_asm(
        self, clause: FactorClause, reg: str, reg_bit_size: int
    ) -> Iterator[bytes]:
        scratch_reg = next(
            reg.name
            for reg in self.segment.scratch_regs
            if reg.bit_size == reg_bit_size
        )
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


# TODO: AdditionSubtractionInversionInstructionPass
