from __future__ import annotations

import binascii
import logging
import textwrap
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal, cast

from capstone import CS_OP_IMM, CS_OP_MEM, CS_OP_REG, CsError, CsInsn

from int3.architecture import Architecture, RegisterDef
from int3.assembly import assemble, disassemble
from int3.errors import Int3CodeGenerationError, Int3MissingEntityError

if TYPE_CHECKING:
    from int3.platform import Triple

type PointerDesc = Literal["", "byte ptr", "dword ptr", "qword ptr"]

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class MemoryOperand:
    reg: RegisterDef
    offset: int
    ptr_desc: PointerDesc = ""

    def __str__(self) -> str:
        deref_str: str
        if self.offset == 0:
            deref_str = f"[{self.reg}]"
        elif self.offset < 0:
            deref_str = f"[{self.reg} - {abs(self.offset)}]"
        else:
            deref_str = f"[{self.reg} + {self.offset}]"

        if not self.ptr_desc:
            return deref_str
        else:
            return f"{self.ptr_desc} {deref_str}"

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} [{self}]>"


@dataclass(frozen=True)
class OperandView:
    insn: Instruction

    tokens: tuple[str, ...] = field(init=False)

    def __post_init__(self):
        object.__setattr__(
            self,
            "tokens",
            tuple(token.strip() for token in self.insn.op_str.split(",")),
        )

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

    def _fix_index(self, index: int) -> int:
        if len(self) == 0:
            raise Int3CodeGenerationError("Tried to index into an empty operand view")
        elif index < 0 and abs(index) > len(self):
            raise Int3CodeGenerationError(
                f"Negative index {index} is too large for operand view of length {len(self)}"
            )

        if index < 0:
            index += len(self)

        if index >= len(self):
            raise Int3CodeGenerationError(
                f"Index {index} too large for operand view of length {len(self)}"
            )

        return index

    def token(self, index: int) -> str:
        """Retrieve the raw operand token."""
        index = self._fix_index(index)
        return self.tokens[index]

    def is_reg(self, index: int) -> bool:
        index = self._fix_index(index)
        return self._is_cs_type(index, CS_OP_REG)

    def reg(self, index: int) -> RegisterDef:
        index = self._fix_index(index)
        reg_name = cast(
            str, self.cs_insn.reg_name(self.cs_insn.operands[index].value.reg)
        )
        return self.arch.reg(reg_name)

    def is_imm(self, index: int) -> bool:
        index = self._fix_index(index)
        return self._is_cs_type(index, CS_OP_IMM)

    def imm(self, index: int) -> int:
        index = self._fix_index(index)
        return cast(int, self.cs_insn.operands[index].value.imm)

    def is_mem(self, index: int) -> bool:
        index = self._fix_index(index)
        return self._is_cs_type(index, CS_OP_MEM)

    def mem(self, index: int) -> MemoryOperand:
        index = self._fix_index(index)
        cs_mem = self.cs_insn.operands[index].value.mem

        ptr_desc: PointerDesc
        mem_token = self.token(index)
        if mem_token.startswith("["):
            ptr_desc = ""
        elif mem_token.startswith("qword ptr"):
            ptr_desc = "qword ptr"
        elif mem_token.startswith("dword ptr"):
            ptr_desc = "dword ptr"
        elif mem_token.startswith("byte ptr"):
            ptr_desc = "byte ptr"
        else:
            raise Int3CodeGenerationError(f"Unexpected memory token: {mem_token}")

        reg_name = cast(str, self.cs_insn.reg_name(cs_mem.base))
        reg = self.arch.reg(reg_name)
        offset = cast(int, cs_mem.disp)

        return MemoryOperand(reg, offset, ptr_desc)

    def replace(
        self, index: int, operand: int | str | RegisterDef | MemoryOperand
    ) -> Instruction:
        """Replace the operand at the specified index with an immediate or register."""
        index = self._fix_index(index)

        if isinstance(operand, (str, RegisterDef)):
            operand = self.arch.keystone_reg_prefix + str(operand)

        operands: list[int | str | RegisterDef | MemoryOperand] = [
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

        logger.debug(f"Replaced operand index {index} of:")
        logger.debug(f"    {self.insn}")
        logger.debug("To:")
        logger.debug(f"    {new_insn}")

        return new_insn

    def __len__(self) -> int:
        return len(self.cs_insn.operands)


@dataclass(frozen=True)
class Instruction:
    cs_insn: CsInsn
    triple: "Triple"

    raw: bytes = field(init=False)
    mnemonic: str = field(init=False)
    op_str: str = field(init=False)
    operands: OperandView = field(init=False)
    tainted_regs: set[RegisterDef] = field(init=False)

    _cs_group_names: set[str] = field(init=False)

    def __post_init__(self):
        object.__setattr__(self, "raw", self.cs_insn.bytes)
        object.__setattr__(self, "mnemonic", self.cs_insn.mnemonic)
        object.__setattr__(self, "op_str", self._init_op_str())
        object.__setattr__(self, "operands", OperandView(self))

        cs_group_names = [
            self.cs_insn.group_name(group_id) for group_id in self.cs_insn.groups
        ]
        object.__setattr__(self, "_cs_group_names", cs_group_names)

        # We initialize tainted_regs last, as it's the most involved field to
        # initialize and relies on other members of this class already being
        # available.
        object.__setattr__(self, "tainted_regs", self._init_tainted_regs())

    def _init_op_str(self) -> str:
        cs_op_str = cast(str, self.cs_insn.op_str)
        return cs_op_str

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

    def __bytes__(self) -> bytes:
        return bytes(self.raw)

    def __str__(self) -> str:
        return self.to_str()

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} [{self}]>"

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

    def is_call(self) -> bool:
        return "call" in self._cs_group_names

    def is_branch(self) -> bool:
        return "branch_relative" in self._cs_group_names

    def is_syscall(self) -> bool:
        return self.mnemonic.startswith("syscall")

    def is_mov(self) -> bool:
        mov_needles = ["mov", "lea", "li", "lui"]
        return any(self.mnemonic.startswith(needle) for needle in mov_needles)

    def is_add(self) -> bool:
        return self.mnemonic.startswith("add")

    def is_sub(self) -> bool:
        return self.mnemonic.startswith("sub")

    def is_or(self) -> bool:
        return self.mnemonic.startswith("or")

    def is_and(self) -> bool:
        return self.mnemonic.startswith("and")

    def is_pop(self) -> bool:
        return self.mnemonic.startswith("pop")

    def is_push(self) -> bool:
        return self.mnemonic.startswith("push")

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
    def from_str(raw: str, triple: "Triple") -> tuple[Instruction, ...]:
        raw_asm = assemble(arch=triple.arch, assembly=raw)
        return Instruction.from_bytes(raw_asm, triple)

    @staticmethod
    def from_bytes(raw: bytes, triple: "Triple") -> tuple[Instruction, ...]:
        return tuple(
            Instruction(cs_insn=cs_insn, triple=triple)
            for cs_insn in disassemble(arch=triple.arch, machine_code=raw)
        )
