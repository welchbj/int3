import logging
from dataclasses import dataclass

from int3.errors import Int3CodeGenerationError
from int3.platform import Triple

from .code_segment import CodeSegment
from .instruction import Instruction
from .passes import (
    InstructionMutationPass,
    InvertAddOrSubImmediateInstructionPass,
    MoveFactorImmediateInstructionPass,
    MoveSmallImmediateInstructionPass,
)

logger = logging.getLogger(__name__)


@dataclass
class MutationEngine:
    triple: Triple
    raw_asm: bytes
    bad_bytes: bytes

    def _create_instruction_passes(
        self, segment: CodeSegment
    ) -> list[InstructionMutationPass]:
        pass_classes = [
            MoveSmallImmediateInstructionPass,
            MoveFactorImmediateInstructionPass,
            InvertAddOrSubImmediateInstructionPass,
        ]
        return [cls(segment, self.bad_bytes) for cls in pass_classes]  # type: ignore

    def clean(self) -> CodeSegment:
        mutated_segment = CodeSegment(
            triple=self.triple,
            raw_asm=self.raw_asm,
            bad_bytes=self.bad_bytes,
        )
        if mutated_segment.is_clean:
            return mutated_segment

        # Apply instruction-level passes.
        insn_passes = self._create_instruction_passes(mutated_segment)
        new_insn_list: list[Instruction] = []
        for insn in mutated_segment.instructions:
            # Simply record the instruction if it doesn't contain bad bytes.
            if not insn.is_dirty(self.bad_bytes):
                new_insn_list.append(insn)
                continue

            # TODO: We need logic to discern between instruction passes that
            #       will break relative jumps.

            for insn_pass in insn_passes:
                if not insn_pass.should_mutate(insn):
                    logger.debug(f"Skipping {insn_pass.__class__.__name__} for {insn}")
                    continue

                try:
                    logger.info(f"Invoking {insn_pass.__class__.__name__} for {insn}")
                    mutated_insns = insn_pass.mutate(insn)
                except Int3CodeGenerationError as e:
                    logger.info(f"{insn_pass.__class__.__name__} failed: {e}")
                    continue

                if not any(insn.is_dirty(self.bad_bytes) for insn in mutated_insns):
                    # This set of instructions is a bad byte compliant mutation of the input
                    # instruction.
                    new_insn_list.extend(mutated_insns)

                    logger.info(f"{insn_pass.__class__.__name__} transformed:")
                    logger.info(f"{Instruction.summary(insn, indent=4)[0]}")
                    logger.info("into:")
                    for line in Instruction.summary(*mutated_insns, indent=4):
                        logger.info(line)
                    break
            else:
                new_insn_list.append(insn)
                logger.info("Instruction-level passes could not remove bad bytes from:")
                logger.info(f"{Instruction.summary(insn, indent=4)[0]}")

        new_program = b"".join(bytes(insn) for insn in new_insn_list)
        mutated_segment = CodeSegment(
            triple=self.triple, raw_asm=new_program, bad_bytes=self.bad_bytes
        )

        if mutated_segment.is_clean:
            return mutated_segment

        dirty_insn_lines = Instruction.summary(
            *mutated_segment.dirty_instructions, indent=4
        )
        all_insn_lines = Instruction.summary(*mutated_segment.instructions, indent=4)
        raise Int3CodeGenerationError(
            "\n\nUnable to clean bad bytes from the following instructions:\n"
            + "\n".join(dirty_insn_lines)
            + "\n"
            + "Full segment:\n"
            + "\n".join(all_insn_lines)
        )
