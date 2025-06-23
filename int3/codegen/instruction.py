from __future__ import annotations

import binascii
import logging
import textwrap
from dataclasses import dataclass, field
from typing import cast

from capstone import CS_OP_IMM, CS_OP_REG, CsInsn

from int3.architecture import Architecture, RegisterDef
from int3.assembly import disassemble
from int3.errors import Int3CodeGenerationError, Int3MissingEntityError

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

    def __len__(self) -> int:
        return len(self.cs_insn.operands)


@dataclass(frozen=True)
class Instruction:
    cs_insn: CsInsn
    arch: Architecture

    raw: bytes = field(init=False)
    mnemonic: str = field(init=False)
    operands: OperandView = field(init=False)
    tainted_regs: set[RegisterDef] = field(init=False)

    def __post_init__(self):
        object.__setattr__(self, "raw", self.cs_insn.bytes)
        object.__setattr__(self, "mnemonic", self.cs_insn.mnemonic)
        object.__setattr__(self, "operands", OperandView(self))
        object.__setattr__(self, "tainted_regs", self._init_tainted_regs())

    def _init_tainted_regs(self) -> set[RegisterDef]:
        tainted_regs = set()
        for cs_reg_id in self.cs_insn.regs_write:
            reg_name = self.cs_insn.reg_name(cs_reg_id)
            try:
                reg = self.arch.reg(reg_name)
            except Int3MissingEntityError as e:
                logger.debug(f"Skipping reported tainted reg: {reg_name}")
                continue

            tainted_regs |= set(self.arch.expand_regs(reg))

        return tainted_regs

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
            line += f"({asm_hex})"
        return line

    def is_dirty(self, bad_bytes: bytes) -> bool:
        return any(b in self.raw for b in bad_bytes)

    def is_mov(self) -> bool:
        # XXX: This is kind of a lazy approach that might be inaccurate.
        return self.mnemonic.startswith("mov")

    def is_add(self) -> bool:
        # XXX: This is kind of a lazy approach that might be inaccurate.
        return self.mnemonic.startswith("add")

    def is_sub(self) -> bool:
        # XXX: This is kind of a lazy approach that might be inaccurate.
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
    def from_bytes(raw: bytes, arch: Architecture) -> tuple[Instruction, ...]:
        return tuple(
            Instruction(cs_insn=cs_insn, arch=arch)
            for cs_insn in disassemble(arch=arch, machine_code=raw)
        )
