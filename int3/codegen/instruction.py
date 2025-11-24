from __future__ import annotations

import binascii
import logging
import re
import textwrap
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal, cast

from capstone import CS_OP_IMM, CS_OP_MEM, CS_OP_REG, CsError, CsInsn

from int3.architecture import Architecture, Architectures, RegisterDef
from int3.assembly import assemble, disassemble
from int3.errors import (
    Int3ArgumentError,
    Int3CodeGenerationError,
    Int3MissingEntityError,
)

if TYPE_CHECKING:
    from int3.platform import Triple

type PointerDesc = Literal["", "byte ptr", "dword ptr", "qword ptr"]
type ParsedToken = str | RegisterListOperand

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class MemoryOperand:
    """Specialized operand type for representing memory access."""

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
class RegisterListOperand:
    """Specialized operand type for ARM register lists (push/pop/ldm/stm)."""

    regs: tuple[RegisterDef, ...]

    def __str__(self) -> str:
        sorted_regs = sorted(self.regs, key=self._reg_sort_key)
        return "{" + ", ".join(str(r) for r in sorted_regs) + "}"

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} [{self}]>"

    def __contains__(self, reg: RegisterDef) -> bool:
        return reg in self.regs

    def __iter__(self):
        return iter(self.regs)

    def __len__(self) -> int:
        return len(self.regs)

    def with_replaced(self, index: int, new_reg: RegisterDef) -> RegisterListOperand:
        """Return a new instance with the register at the specified index replaced."""
        regs = list(self.regs)
        regs[index] = new_reg
        return RegisterListOperand(tuple(regs))

    @staticmethod
    def _reg_sort_key(reg: RegisterDef) -> tuple[int, str, int]:
        """Sort key for natural register ordering (r0 < r1 < ... < r9 < r10).

        Uses reg_num when available for canonical ordering of aliased registers.

        """
        if reg.reg_num is not None:
            return (0, "", reg.reg_num)

        match = re.match(r"^([a-zA-Z]+)(\d+)$", reg.name)
        if match:
            return (1, match.group(1), int(match.group(2)))

        return (2, reg.name, 0)

    @classmethod
    def of(cls, arch: Architecture, *regs: RegisterDef | str) -> RegisterListOperand:
        """Create a register list from RegisterDef instances or string names."""
        normalized = tuple(arch.reg(r) if isinstance(r, str) else r for r in regs)
        return cls(normalized)

    @classmethod
    def from_token(cls, token: str, arch: Architecture) -> RegisterListOperand:
        """Parse a register list token like '{r0, r1, r2}'."""
        if not (token.startswith("{") and token.endswith("}")):
            raise Int3CodeGenerationError(f"Invalid register list token: {token}")

        inner = token[1:-1]
        reg_strs = [r.strip() for r in inner.split(",") if r.strip()]
        regs = tuple(arch.reg(r) for r in reg_strs)
        return cls(regs)


@dataclass(frozen=True)
class OperandView:
    """A view into an instruction's operands."""

    insn: Instruction

    _parsed_tokens: tuple[ParsedToken, ...] = field(init=False, compare=False)
    _operand_mapping: tuple[tuple[int, int | None], ...] = field(
        init=False, compare=False
    )

    def __post_init__(self):
        parsed_tokens, mapping = self._parse_operands(self.insn.op_str, self.arch)
        object.__setattr__(self, "_parsed_tokens", parsed_tokens)
        object.__setattr__(self, "_operand_mapping", mapping)

    @property
    def tokens(self) -> tuple[str, ...]:
        """Raw strings of the tokens contained within this operand string."""
        return tuple(str(t) for t in self._parsed_tokens)

    @staticmethod
    def _parse_operands(
        op_str: str,
        arch: Architecture,
    ) -> tuple[tuple[ParsedToken, ...], tuple[tuple[int, int | None], ...]]:
        raw_tokens: list[str] = []
        current = ""
        in_braces = False

        for char in op_str:
            if char == "{":
                in_braces = True
                current += char
            elif char == "}":
                in_braces = False
                current += char
            elif char == "," and not in_braces:
                raw_tokens.append(current.strip())
                current = ""
            else:
                current += char

        if current.strip():
            raw_tokens.append(current.strip())

        parsed_tokens: list[ParsedToken] = []
        mapping: list[tuple[int, int | None]] = []

        for tok_idx, token in enumerate(raw_tokens):
            if token.startswith("{") and token.endswith("}"):
                reg_list = RegisterListOperand.from_token(token, arch)
                parsed_tokens.append(reg_list)
                for pos in range(len(reg_list)):
                    mapping.append((tok_idx, pos))
            else:
                parsed_tokens.append(token)
                mapping.append((tok_idx, None))

        return tuple(parsed_tokens), tuple(mapping)

    @property
    def cs_insn(self) -> CsInsn:
        """The underlying Capstone instruction instance."""
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
        """Retrieve the raw operand token for the given operand index.

        For register list operands, this returns the full register list token
        (e.g., ``{r0, r1, r2}``), not the individual register.

        """
        index = self._fix_index(index)
        tok_idx, _ = self._operand_mapping[index]
        return str(self._parsed_tokens[tok_idx])

    def is_reg_list(self, index: int) -> bool:
        """Whether the operand at the specific position is part of a register list."""
        index = self._fix_index(index)
        _, list_pos = self._operand_mapping[index]
        return list_pos is not None

    def reg_list(self, index: int) -> RegisterListOperand:
        """Get the register list containing the operand at the specific position."""
        index = self._fix_index(index)
        tok_idx, list_pos = self._operand_mapping[index]
        if list_pos is None:
            raise Int3ArgumentError(
                f"Operand at index {index} is not part of a register list"
            )

        token = self._parsed_tokens[tok_idx]
        return cast(RegisterListOperand, token)

    def is_reg(self, index: int) -> bool:
        """Whether the operand at the specific position is a register."""
        index = self._fix_index(index)
        return self._is_cs_type(index, CS_OP_REG)

    def reg(self, index: int) -> RegisterDef:
        """Get the register definition at the specific operand position."""
        index = self._fix_index(index)
        reg_name = cast(
            str, self.cs_insn.reg_name(self.cs_insn.operands[index].value.reg)
        )
        return self.arch.reg(reg_name)

    def is_imm(self, index: int) -> bool:
        """Whether the operand at the specific position is an immediate."""
        index = self._fix_index(index)
        return self._is_cs_type(index, CS_OP_IMM)

    def imm(self, index: int) -> int:
        """Get the immediate at the specific operand position"""
        index = self._fix_index(index)
        return cast(int, self.cs_insn.operands[index].value.imm)

    def is_mem(self, index: int) -> bool:
        """Whether the operand at the specific position is a memory access."""
        index = self._fix_index(index)
        return self._is_cs_type(index, CS_OP_MEM)

    def mem(self, index: int) -> MemoryOperand:
        """Get the memory access operand at the specific operand position"""
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
        """Replace the operand at the specified index with an immediate or register.

        This method handles both regular operands and registers within ARM-style
        register lists (e.g., replacing r8 in ``pop {r4, r8}``).

        """
        index = self._fix_index(index)
        tok_idx, list_pos = self._operand_mapping[index]
        new_tokens: list[ParsedToken] = list(self._parsed_tokens)

        if list_pos is not None:
            # Replace within a register list.
            if isinstance(operand, str):
                operand = self.arch.reg(operand)

            if not isinstance(operand, RegisterDef):
                raise Int3ArgumentError(
                    f"Cannot replace register in list with {type(operand).__name__}"
                )

            token = cast(RegisterListOperand, new_tokens[tok_idx])
            new_tokens[tok_idx] = token.with_replaced(list_pos, operand)
        else:
            if isinstance(operand, (str, RegisterDef)):
                new_tokens[tok_idx] = self.arch.keystone_reg_prefix + str(operand)
            elif isinstance(operand, MemoryOperand):
                new_tokens[tok_idx] = str(operand)
            else:
                new_tokens[tok_idx] = str(operand)

        mnemonic = self._normalize_mnemonic(index, operand)
        new_insn_str = f"{mnemonic} {', '.join(str(t) for t in new_tokens)}"

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

    def _normalize_mnemonic(
        self,
        replaced_index: int,
        operand: int | str | RegisterDef | MemoryOperand,
    ) -> str:
        """Normalize mnemonic when operand type changes between immediate and register."""
        mnemonic = self.insn.mnemonic
        was_imm = self.is_imm(replaced_index)
        was_reg = self.is_reg(replaced_index)
        is_now_reg = isinstance(operand, (str, RegisterDef, MemoryOperand))
        is_now_imm = isinstance(operand, int)

        match self.arch:
            case Architectures.Mips.value:
                if was_imm and is_now_reg:
                    # Immediate to Register: strip 'i'/'iu' suffix.
                    if mnemonic.endswith("iu"):
                        return mnemonic[:-2] + "u"
                    if mnemonic.endswith("i") and mnemonic not in ("li", "lui"):
                        return mnemonic[:-1]
                elif was_reg and is_now_imm:
                    # Register to Immediate: add 'i'/'u' suffix.
                    if mnemonic.endswith("u") and not mnemonic.endswith("iu"):
                        return mnemonic[:-1] + "iu"
                    if mnemonic in ("add", "and", "or", "xor"):
                        return mnemonic + "i"

        return mnemonic

    def __len__(self) -> int:
        return len(self.cs_insn.operands)


@dataclass(frozen=True)
class Instruction:
    """Wrapper around a machine code instruction."""

    cs_insn: CsInsn = field(compare=False)
    triple: "Triple" = field(compare=True)

    raw: bytes = field(init=False, compare=True)
    mnemonic: str = field(init=False, compare=False)
    op_str: str = field(init=False, compare=False)
    operands: OperandView = field(init=False, compare=False)
    tainted_regs: set[RegisterDef] = field(init=False, compare=False)
    regs_read: frozenset[RegisterDef] = field(init=False, compare=False)
    regs_written: frozenset[RegisterDef] = field(init=False, compare=False)

    _cs_group_names: set[str] = field(init=False, compare=False)

    def __post_init__(self):
        object.__setattr__(self, "raw", self.cs_insn.bytes)
        object.__setattr__(self, "mnemonic", self.cs_insn.mnemonic)
        object.__setattr__(self, "op_str", self._init_op_str())
        object.__setattr__(self, "operands", OperandView(self))

        cs_group_names = [
            self.cs_insn.group_name(group_id) for group_id in self.cs_insn.groups
        ]
        object.__setattr__(self, "_cs_group_names", cs_group_names)

        # We initialize these register sets last, as they are the most
        # involved fields to initialize and rely on other members of
        # this class already being available.
        object.__setattr__(self, "regs_read", self._init_regs_read())
        object.__setattr__(self, "regs_written", self._init_regs_written())
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

    @property
    def asm_str(self) -> str:
        return f"{self.mnemonic} {self.op_str}"

    def __bytes__(self) -> bytes:
        return bytes(self.raw)

    def __str__(self) -> str:
        return self.to_str()

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} [{self}]>"

    def to_str(self, alignment: int = 0, with_hex: bool = True) -> str:
        """Pretty print this instructions mnemonic and operands."""
        asm_hex = binascii.hexlify(self.raw).decode()
        line = self.asm_str
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
        return self.mnemonic.startswith("syscall") or self.mnemonic.startswith("svc")

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

    def is_xor(self) -> bool:
        return self.mnemonic.startswith("xor") or self.mnemonic.startswith("eor")

    def is_pop(self) -> bool:
        return self.mnemonic.startswith("pop")

    def is_push(self) -> bool:
        return self.mnemonic.startswith("push")

    def is_nop(self) -> bool:
        return self.mnemonic == "nop"

    def has_only_register_operands(self) -> bool:
        if len(self.operands) == 0:
            return False

        return all(self.operands.is_reg(i) for i in range(len(self.operands)))

    def _init_regs_read(self) -> frozenset[RegisterDef]:
        """Registers read by this instruction."""
        try:
            regs_read_ids, _ = self.cs_insn.regs_access()
            reg_names = {self.cs_insn.reg_name(r) for r in regs_read_ids}
        except CsError:
            # Fallback: assume all non-destination operands are read.
            #
            # XXX: Some special cases like jumps.
            reg_names = set()
            for i in range(1, len(self.operands)):
                if self.operands.is_reg(i):
                    reg_names.add(self.operands.reg(i).name)

        result = set()
        for name in reg_names:
            try:
                result.add(self.arch.reg(name))
            except Int3MissingEntityError:
                logger.debug(f"Skipping unknown read register: {name}")
        return frozenset(result)

    def _init_regs_written(self) -> frozenset[RegisterDef]:
        """Registers written by this instruction."""
        try:
            _, regs_write_ids = self.cs_insn.regs_access()
            reg_names = {self.cs_insn.reg_name(r) for r in regs_write_ids}
        except CsError:
            # Fallback: assume first operand is written if it's a register.
            #
            # XXX: Some special cases like jumps.
            reg_names = set()
            if len(self.operands) >= 1 and self.operands.is_reg(0):
                reg_names.add(self.operands.reg(0).name)

        result = set()
        for name in reg_names:
            try:
                result.add(self.arch.reg(name))
            except Int3MissingEntityError:
                logger.debug(f"Skipping unknown write register: {name}")
        return frozenset(result)

    @staticmethod
    def summary(*insns: Instruction, indent: int = 0) -> list[str]:
        """Summary text for a sequence of instructions."""
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
        """Factory method to produce an instruction from assembly text."""
        raw_asm = assemble(arch=triple.arch, assembly=raw)
        return Instruction.from_bytes(raw_asm, triple)

    @staticmethod
    def from_bytes(raw: bytes, triple: "Triple") -> tuple[Instruction, ...]:
        """Factory method to produce an instruction from machine code bytes."""
        return tuple(
            Instruction(cs_insn=cs_insn, triple=triple)
            for cs_insn in disassemble(arch=triple.arch, machine_code=raw)
        )
