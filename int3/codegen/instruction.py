from __future__ import annotations

import binascii
import logging
import textwrap
from dataclasses import dataclass, field
from typing import cast

from capstone import CS_OP_IMM, CS_OP_REG, CsError, CsInsn

from int3.architecture import Architecture, RegisterDef
from int3.assembly import assemble, disassemble
from int3.errors import Int3CodeGenerationError, Int3MissingEntityError
from int3.platform import Triple

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class OperandView:
    insn: Instruction

    @property
    def cs_insn(self) -> CsInsn:
        return self.insn.cs_insn

    @property
    def arch(self) -> Architecture:
        return self.insn.arch

    def _is_cs_type(self, index: int, cs_type: int) -> bool:
        if index >= len(self):
            raise Int3CodeGenerationError(
                f"Index {index} too large; only {len(self)} operands"
            )

        operand_type = cast(int, self.cs_insn.operands[index].type)
        return operand_type == cs_type

    def is_reg(self, index: int) -> bool:
        return self._is_cs_type(index, CS_OP_REG)

    def reg(self, index: int) -> RegisterDef:
        reg_name = cast(
            str, self.cs_insn.reg_name(self.cs_insn.operands[index].value.reg)
        )
        return self.arch.reg(reg_name)

    def is_imm(self, index: int) -> bool:
        return self._is_cs_type(index, CS_OP_IMM)

    def imm(self, index: int) -> int:
        return cast(int, self.cs_insn.operands[index].value.imm)

    def replace(self, index: int, operand: int | RegisterDef) -> Instruction:
        """Replace the operand at the specified index with an immediate or register."""
        operands: list[int | str | RegisterDef] = [
            token.strip() for token in self.insn.op_str.split(",")
        ]
        operands[index] = operand

        new_insn_str = self.insn.mnemonic
        new_insn_str += " "
        new_insn_str += ", ".join(str(o) for o in operands)

        new_machine_code = assemble(arch=self.arch, assembly=new_insn_str)
        new_cs_insns = disassemble(arch=self.arch, machine_code=new_machine_code)
        if len(new_cs_insns) != 1:
            raise Int3CodeGenerationError(
                f"Replacing operand {index} in {self.insn} turned it into {len(new_cs_insns)} "
                f"instructions: {', '.join(new_cs_insns)}"
            )

        new_cs_insn = new_cs_insns[0]
        new_insn = Instruction(cs_insn=new_cs_insn, triple=self.insn.triple)

        logger.info(f"Replaced operand index {index} of:")
        logger.info(f"    {self.insn}")
        logger.info(f"To:")
        logger.info(f"    {new_insn}")

        return new_insn

    def __len__(self) -> int:
        return len(self.cs_insn.operands)


@dataclass(frozen=True)
class Instruction:
    cs_insn: CsInsn
    triple: Triple

    raw: bytes = field(init=False)
    mnemonic: str = field(init=False)
    operands: OperandView = field(init=False)
    tainted_regs: set[RegisterDef] = field(init=False)

    _cs_group_names: set[str] = field(init=False)

    def __post_init__(self):
        object.__setattr__(self, "raw", self.cs_insn.bytes)
        object.__setattr__(self, "mnemonic", self.cs_insn.mnemonic)
        object.__setattr__(self, "operands", OperandView(self))

        cs_group_names = [
            self.cs_insn.group_name(group_id) for group_id in self.cs_insn.groups
        ]
        object.__setattr__(self, "_cs_group_names", cs_group_names)

        # We initialize tainted_regs last, as it's the most involved field to
        # initialize and relies on other members of this class already being
        # available.
        object.__setattr__(self, "tainted_regs", self._init_tainted_regs())

    def _init_tainted_regs(self) -> set[RegisterDef]:
        regs_written: list[str | RegisterDef] = []

        # Captsone is not aware of syscall conventions, so we handle this
        # special case first.
        if self.is_syscall():
            regs_written.append(self.triple.syscall_convention.result)

        try:
            # Ideally, we will get the tainted register names from Captone's
            # semantic understanding of the instruction.
            _, regs_written_cs_id = self.cs_insn.regs_access()
            regs_written.extend(
                self.cs_insn.reg_name(cs_reg_id) for cs_reg_id in regs_written_cs_id
            )
        except CsError:
            # If that's not supported on an architecture, we assume the
            # destination register of the operation is tainted.
            if self.is_jump() or self.is_branch():
                pass
            elif len(self.operands) >= 1 and self.operands.is_reg(0):
                regs_written.append(self.operands.reg(0))
            else:
                pass

        tainted_regs = set()
        for reg_or_str in regs_written:
            try:
                if isinstance(reg_or_str, str):
                    reg = self.arch.reg(reg_or_str)
                else:
                    reg = reg_or_str
            except Int3MissingEntityError:
                logger.debug(f"Skipping unexpected reported tainted reg: {reg_or_str}")
                continue

            tainted_regs |= set(self.arch.expand_regs(reg))

        return tainted_regs

    @property
    def arch(self) -> Architecture:
        return self.triple.arch

    @property
    def op_str(self) -> str:
        return cast(str, self.cs_insn.op_str)

    def __bytes__(self) -> bytes:
        return bytes(self.raw)

    def __str__(self) -> str:
        return self.to_str()

    def to_str(self, alignment: int = 0, with_hex: bool = True) -> str:
        asm_hex = binascii.hexlify(self.raw).decode()
        line = f"{self.mnemonic} {self.op_str}"
        if with_hex:
            alignment += 1
        line = line.ljust(alignment, " ")
        if with_hex:
            line += f" ({asm_hex})"
        return line

    def is_dirty(self, bad_bytes: bytes) -> bool:
        return any(b in self.raw for b in bad_bytes)

    def is_jump(self) -> bool:
        return "jump" in self._cs_group_names

    def is_branch(self) -> bool:
        return "branch_relative" in self._cs_group_names

    def is_syscall(self) -> bool:
        return self.mnemonic.startswith("syscall")

    def is_mov(self) -> bool:
        return self.mnemonic.startswith("mov")

    def is_add(self) -> bool:
        return self.mnemonic.startswith("add")

    def is_sub(self) -> bool:
        return self.mnemonic.startswith("sub")

    @staticmethod
    def summary(*insns: Instruction, indent: int = 0) -> list[str]:
        max_insn_str_len = max(len(insn.to_str(with_hex=False)) for insn in insns)

        dirty_insn_lines: list[str] = []
        for insn in insns:
            line = insn.to_str(alignment=max_insn_str_len)
            dirty_insn_lines.append(line)

        return textwrap.indent(
            "\n".join(dirty_insn_lines), prefix=" " * indent
        ).splitlines()

    @staticmethod
    def from_bytes(raw: bytes, triple: Triple) -> tuple[Instruction, ...]:
        return tuple(
            Instruction(cs_insn=cs_insn, triple=triple)
            for cs_insn in disassemble(arch=triple.arch, machine_code=raw)
        )
