import logging

from int3.codegen import Choice, Instruction
from int3.errors import Int3CodeGenerationError

from .abc import InstructionMutationPass

logger = logging.getLogger(__name__)

# Varied terminal offsets providing byte diversity in final load/store encoding.
# Includes small offsets for loads and larger offsets (>= 512) for AArch64 stores
# which avoid null bytes in the immediate field.
_TERMINAL_OFFSETS = (8, 16, 64, 128, 256, 512, 520, 528)


class MemoryOffsetInstructionPass(InstructionMutationPass):
    """Mutate load/store by recomputing the effective address in a scratch register."""

    def should_mutate(self, insn: Instruction) -> bool:
        return (
            (insn.is_load() or insn.is_store())
            and not insn.is_pre_indexed()
            and not insn.is_post_indexed()
        )

    def mutate(self, insn: Instruction) -> Choice:
        mem_op = insn.memory_operand()
        base_reg = mem_op.reg
        original_offset = mem_op.offset
        data_reg = insn.operands.reg(0)
        scratch_regs = self.segment.scratch_regs_for_size(base_reg.bit_size)

        usable = [r for r in scratch_regs if r not in (base_reg, data_reg)]
        if len(usable) < 2:
            return self.codegen.choice(insn)

        addr_scratch = usable[0]
        delta_scratch = usable[1]
        remaining = tuple(usable[2:])

        options = []
        for terminal in _TERMINAL_OFFSETS:
            delta = original_offset - terminal

            try:
                if delta == 0:
                    factored = self.codegen.ll_clear(delta_scratch)
                    addr_setup = self.codegen.add(addr_scratch, base_reg, delta_scratch)
                elif delta > 0:
                    factored = self.codegen.hl_put_imm(
                        delta, delta_scratch, remaining, self.bad_bytes
                    )
                    addr_setup = self.codegen.add(addr_scratch, base_reg, delta_scratch)
                else:
                    factored = self.codegen.hl_put_imm(
                        -delta, delta_scratch, remaining, self.bad_bytes
                    )
                    addr_setup = self.codegen.sub(addr_scratch, base_reg, delta_scratch)
            except Int3CodeGenerationError as e:
                logger.debug(f"Skipping terminal {terminal}: {e}")
                continue

            access = (
                self.codegen.load(data_reg, addr_scratch, terminal)
                if insn.is_load()
                else self.codegen.store(data_reg, addr_scratch, terminal)
            )

            options.append(self.codegen.segment(factored, addr_setup, access))

        return self.codegen.choice(*options) if options else self.codegen.choice(insn)
