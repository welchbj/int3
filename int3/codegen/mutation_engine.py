import binascii
import logging
import textwrap
from dataclasses import dataclass
from typing import Sequence

from capstone import CsInsn

from int3.architecture import Architecture
from int3.assembly import disassemble
from int3.errors import Int3CodeGenerationError

from .compiled_segment import CompiledSegment
from .passes import (
    InstructionMutationPass,
    MoveFactorImmediateInstructionPass,
    MoveSmallImmediateInstructionPass,
)

logger = logging.getLogger(__name__)


@dataclass
class MutationEngine:
    arch: Architecture
    raw_asm: bytes
    bad_bytes: bytes

    def _is_dirty(self, insn: CsInsn | bytes) -> bool:
        if isinstance(insn, CsInsn):
            insn = insn.bytes

        return any(b in insn for b in self.bad_bytes)

    def _create_instruction_passes(
        self, segment: CompiledSegment
    ) -> list[InstructionMutationPass]:
        pass_classes: list[type[InstructionMutationPass]] = [
            MoveSmallImmediateInstructionPass,
            MoveFactorImmediateInstructionPass,
        ]
        return [cls(segment, self.bad_bytes) for cls in pass_classes]

    @staticmethod
    def instruction_summary(insns: Sequence[CsInsn], indent: int = 0) -> list[str]:
        max_op_str_len = max(len(insn.op_str) for insn in insns)

        dirty_insn_lines: list[str] = []
        for insn in insns:
            mnemonic: str = insn.mnemonic
            op_str: str = insn.op_str
            asm_hex = binascii.hexlify(insn.bytes).decode()

            line = f"{mnemonic} "
            line += op_str.ljust(max_op_str_len + 1, " ")
            line += f"({asm_hex})"
            dirty_insn_lines.append(line)

        return textwrap.indent(
            "\n".join(dirty_insn_lines), prefix=" " * indent
        ).splitlines()

    def clean(self) -> CompiledSegment:
        mutated_segment = CompiledSegment(
            arch=self.arch,
            raw_asm=self.raw_asm,
            bad_bytes=self.bad_bytes,
        )
        if mutated_segment.is_clean:
            return mutated_segment

        # Apply instruction-level passes.
        insn_passes = self._create_instruction_passes(mutated_segment)
        new_program = b""
        for insn in mutated_segment.all_instructions:
            # Simply record the instruction if it doesn't contain bad bytes.
            if not self._is_dirty(insn):
                new_program += insn.bytes
                continue

            # TODO: Dissolve the concept of instruction-level passes.

            # TODO: We need logic to discern between instruction passes that
            #       will break relative jumps.

            for insn_pass in insn_passes:
                mutated_bytes = insn_pass.mutate_instruction(insn)
                if mutated_bytes and not self._is_dirty(mutated_bytes):
                    new_program += mutated_bytes

                    mutated_insns = disassemble(self.arch, mutated_bytes)
                    logger.debug(f"{insn_pass.__class__.__name__} transformed:")
                    logger.debug(f"{self.instruction_summary([insn], indent=4)[0]}")
                    logger.debug("into:")
                    for line in self.instruction_summary(mutated_insns, indent=4):
                        logger.debug(line)
                    break
            else:
                new_program += insn.bytes
                logger.debug(
                    "Instruction-level passes could not remove bad bytes from:"
                )
                logger.debug(f"{self.instruction_summary([insn], indent=4)[0]}")

        mutated_segment = CompiledSegment(
            arch=self.arch, raw_asm=new_program, bad_bytes=self.bad_bytes
        )

        # Apply segment-level passes.
        # TODO

        if mutated_segment.is_clean:
            return mutated_segment

        dirty_insn_lines = self.instruction_summary(
            mutated_segment.dirty_instructions, indent=4
        )
        raise Int3CodeGenerationError(
            "Unable to clean bad bytes from the following instructions:\n"
            + "\n".join(dirty_insn_lines)
        )
