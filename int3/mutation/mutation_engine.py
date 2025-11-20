import logging
from dataclasses import dataclass

from int3.codegen import Instruction, Segment
from int3.errors import Int3CodeGenerationError
from int3.platform import Triple

from .passes import (
    AddSyscallOperandInstructionPass,
    FactorImmediateViaTransitoryRegisterInstructionPass,
    FactorInplaceImmediateInstructionPass,
    InstructionMutationPass,
    MipsReturnInstructionPass,
    MoveSmallImmediateInstructionPass,
    NopRewriterInstructionPass,
)

logger = logging.getLogger(__name__)


@dataclass
class MutationEngine:
    """Engine for managing code mutation passes applied to machine code."""

    triple: Triple
    raw_asm: bytes
    bad_bytes: bytes

    def _create_instruction_passes(
        self, segment: Segment
    ) -> list[InstructionMutationPass]:
        pass_classes = [
            AddSyscallOperandInstructionPass,
            MipsReturnInstructionPass,
            NopRewriterInstructionPass,
            FactorInplaceImmediateInstructionPass,
            MoveSmallImmediateInstructionPass,
            FactorImmediateViaTransitoryRegisterInstructionPass,
        ]
        return [cls(segment, self.bad_bytes) for cls in pass_classes]  # type: ignore

    def clean(self) -> Segment:
        """Attempt to clean bad bytes from the machine code wrapped by this engine."""
        mutated_segment = Segment.from_bytes(triple=self.triple, raw_asm=self.raw_asm)
        if not mutated_segment.is_dirty(self.bad_bytes):
            return mutated_segment

        # Apply instruction-level passes.
        insn_passes = self._create_instruction_passes(mutated_segment)
        did_change_segment_len = False
        new_insn_list: list[Instruction] = []
        for original_insn in mutated_segment.insns:
            # Simply record the instruction if it doesn't contain bad bytes.
            if not original_insn.is_dirty(self.bad_bytes):
                new_insn_list.append(original_insn)
                continue

            # Otherwise, we try to apply instruction passes to remove bad bytes.
            for insn_pass in insn_passes:
                if not insn_pass.should_mutate(original_insn):
                    logger.debug(
                        f"Skipping {insn_pass.__class__.__name__} for {original_insn}"
                    )
                    continue

                try:
                    logger.info(
                        f"Invoking {insn_pass.__class__.__name__} for {original_insn}"
                    )
                    mutated_segment = insn_pass.mutate(original_insn).choose(
                        bad_bytes=self.bad_bytes
                    )
                except Int3CodeGenerationError as e:
                    logger.info(f"{insn_pass.__class__.__name__} failed: {e}")
                    continue

                if not any(
                    insn.is_dirty(self.bad_bytes) for insn in mutated_segment.insns
                ):
                    # This set of instructions is a bad byte compliant mutation of the input
                    # instruction.
                    new_insn_list.extend(mutated_segment.insns)

                    mutated_len = sum(
                        len(bytes(insn)) for insn in mutated_segment.insns
                    )
                    original_len = len(bytes(original_insn))
                    if mutated_len != original_len:
                        logger.info(
                            f"Mutation modified instruction len from {original_len:#x} "
                            f"to {mutated_len:#x}"
                        )
                        did_change_segment_len = True

                    logger.info(f"{insn_pass.__class__.__name__} transformed:")
                    logger.info(f"{Instruction.summary(original_insn, indent=4)[0]}")
                    logger.info("into:")
                    for line in Instruction.summary(*mutated_segment.insns, indent=4):
                        logger.info(line)
                    break
            else:
                new_insn_list.append(original_insn)
                logger.info("Instruction-level passes could not remove bad bytes from:")
                logger.info(f"{Instruction.summary(original_insn, indent=4)[0]}")

        # If we modified the program length and our program contains relative jumps,
        # we error out to avoid emitting potentially-corrupt programs.
        #
        # In the future, we'll patch these relative jumps to workaround these scenarios.
        relative_insns = [
            insn for insn in new_insn_list if insn.is_branch() or insn.is_jump()
        ]
        if did_change_segment_len and len(relative_insns) > 0:
            all_insn_lines = Instruction.summary(*new_insn_list, indent=4)
            relative_insn_lines = Instruction.summary(*relative_insns, indent=4)
            raise Int3CodeGenerationError(
                "\n\nCode mutations modified segment length, which may break the following instructions:\n\n"
                + "\n".join(relative_insn_lines)
                + "\n\nOriginal segment:\n\n"
                + "\n".join(all_insn_lines)
            )

        new_program = b"".join(bytes(insn) for insn in new_insn_list)
        completed_mutated_segment = Segment.from_bytes(
            triple=self.triple, raw_asm=new_program
        )

        if not completed_mutated_segment.is_dirty(self.bad_bytes):
            return completed_mutated_segment

        # We couldn't overcome the bad bytes, so we raise an informative exception
        # detailing which instructions we couldn't clean.

        dirty_insn_lines = Instruction.summary(
            *completed_mutated_segment.dirty_instructions(self.bad_bytes), indent=4
        )
        all_insn_lines = Instruction.summary(*completed_mutated_segment.insns, indent=4)
        raise Int3CodeGenerationError(
            "\n\nUnable to clean bad bytes from the following instructions:\n"
            + "\n".join(dirty_insn_lines)
            + "\n"
            + "Full segment:\n"
            + "\n".join(all_insn_lines)
        )
