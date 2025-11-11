from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from int3.architecture import Architecture, Architectures, RegisterDef
from int3.errors import Int3CodeGenerationError
from int3.factor import (
    FactorClause,
    FactorContext,
    FactorOperation,
    FactorResult,
    ImmediateMutationContext,
    compute_factor,
)

from .choice import Choice, FluidSegment, Option

if TYPE_CHECKING:
    from int3.platform import Triple

type RegType = RegisterDef | str
type ImmType = int


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CodeGenerator:
    """Common interface for emitting architecture-specific assembly."""

    triple: "Triple"

    @property
    def arch(self) -> Architecture:
        return self.triple.arch

    def choice(self, *options: str | bytes | Option) -> Choice:
        # TODO
        raise NotImplementedError

    def repeat(self, option: Option, num: int) -> FluidSegment:
        # TODO
        raise NotImplementedError

    def segment(self, *components: str | bytes | Option) -> FluidSegment:
        # TODO
        raise NotImplementedError

    def f(self, value: RegType | ImmType) -> str:
        """Format a register or immediate into a Keystone-consumable form."""
        if isinstance(value, str):
            value = self.arch.reg(value)

        if isinstance(value, RegisterDef):
            return f"{self.arch.keystone_reg_prefix}{value}"
        else:
            return f"{value:#x}"

    def nop_pad(self, pad_len: int) -> bytes:
        nop_bytes = self.triple.one_insn_or_raise("nop").raw
        if pad_len % len(nop_bytes):
            raise Int3CodeGenerationError(
                f"Attempted to pad to misaligned length {pad_len:#x}"
            )

        num_repeats = pad_len // len(nop_bytes)
        return nop_bytes * num_repeats

    def syscall(self, value: ImmType | None = None) -> Choice:
        match self.arch:
            case (
                Architectures.x86_64.value
                | Architectures.x86.value
                | Architectures.Mips.value
            ):
                if value is None:
                    return self.choice("syscall")
                else:
                    return self.choice(f"syscall {self.f(value)}")
            case Architectures.Arm.value | Architectures.Aarch64.value:
                if value is None:
                    return self.choice("svc #0")
                else:
                    return self.choice(f"svc {self.f(value)}")
            case _:
                raise NotImplementedError(f"Unhandled architecture: {self.arch.name}")

    def breakpoint(self) -> Choice:
        match self.arch:
            case Architectures.x86_64.value | Architectures.x86.value:
                return self.choice("int3")
            case Architectures.Mips.value:
                return self.choice("break")
            case Architectures.Arm.value | Architectures.Aarch64.value:
                return self.choice("brk #0")
            case _:
                raise NotImplementedError(f"Unhandled architecture: {self.arch.name}")

    def inc(self, reg: RegType) -> Choice:
        match self.arch:
            case Architectures.x86_64.value | Architectures.x86.value:
                return self.choice(f"inc {self.f(reg)}")
            case Architectures.Mips.value:
                return self.choice(f"addi {self.f(reg)}, 0x1")
            case Architectures.Arm.value | Architectures.Aarch64.value:
                return self.choice(f"add {self.f(reg)}, {self.f(reg)}, #1")
            case _:
                raise NotImplementedError(f"Unhandled architecture: {self.arch.name}")

    def xor(self, one: RegType, two: ImmType | RegType) -> Choice:
        match self.arch:
            case (
                Architectures.x86_64.value
                | Architectures.x86.value
                | Architectures.Mips.value
            ):
                return self.choice(f"xor {self.f(one)}, {self.f(two)}")
            case Architectures.Arm.value | Architectures.Aarch64.value:
                return self.choice(f"eor {self.f(one)}, {self.f(one)}, {self.f(two)}")
            case _:
                raise NotImplementedError(f"Unhandled architecture: {self.arch.name}")

    def add(self, one: RegType, two: ImmType | RegType) -> Choice:
        match self.arch:
            case (
                Architectures.x86_64.value
                | Architectures.x86.value
                | Architectures.Mips.value
            ):
                return self.choice(f"add {self.f(one)}, {self.f(two)}")
            case Architectures.Arm.value | Architectures.Aarch64.value:
                return self.choice(f"add {self.f(one)}, {self.f(one)}, {self.f(two)}")
            case _:
                raise NotImplementedError(f"Unhandled architecture: {self.arch.name}")

    def sub(self, one: RegType, two: ImmType | RegType) -> Choice:
        match self.arch:
            case (
                Architectures.x86_64.value
                | Architectures.x86.value
                | Architectures.Mips.value
            ):
                return self.choice(f"sub {self.f(one)}, {self.f(two)}")
            case Architectures.Arm.value | Architectures.Aarch64.value:
                return self.choice(f"sub {self.f(one)}, {self.f(one)}, {self.f(two)}")
            case _:
                raise NotImplementedError(f"Unhandled architecture: {self.arch.name}")

    def mov(self, one: RegType, two: ImmType | RegType) -> Choice:
        match self.arch:
            case Architectures.x86_64.value | Architectures.x86.value:
                return self.choice(f"mov {self.f(one)}, {self.f(two)}")
            case Architectures.Mips.value:
                if isinstance(two, int):
                    return self.choice(f"li {self.f(one)}, {self.f(two)}")
                else:
                    return self.choice(f"move {self.f(one)}, {self.f(two)}")
            case Architectures.Arm.value | Architectures.Aarch64.value:
                return self.choice(f"mov {self.f(one)}, {self.f(two)}")
            case _:
                raise NotImplementedError(f"Unhandled architecture: {self.arch.name}")

    def compute_pc(self, result: RegType) -> Choice:
        """Compute the program counter for the instruction following this gadget."""
        match self.arch:
            case Architectures.x86_64.value:
                return self.choice(f"lea {self.f(result)}, [rip]")
            case Architectures.Mips.value:
                raise Int3CodeGenerationError(
                    "Mips does not support fine-grained PC-relative addressing"
                )
            case Architectures.Arm.value:
                return self.choice(f"mov {self.f(result)}, pc")
            case Architectures.Aarch64.value:
                return self.choice(f"adr {self.f(result)}, .")
            case _:
                raise NotImplementedError(f"Unhandled architecture: {self.arch.name}")

    def jump(self, value: ImmType | RegType) -> Choice:
        match self.arch:
            case Architectures.x86.value | Architectures.x86_64.value:
                return self.choice(f"jmp {self.f(value)}")
            case Architectures.Mips.value:
                if isinstance(value, int):
                    return self.choice(f"j {self.f(value)}")
                else:
                    return self.choice(f"jr {self.f(value)}")
            case Architectures.Arm.value:
                if isinstance(value, int):
                    return self.choice(f"b {self.f(value)}")
                else:
                    return self.choice(f"bx {self.f(value)}")
            case Architectures.Aarch64.value:
                if isinstance(value, int):
                    return self.choice(f"b {self.f(value)}")
                else:
                    return self.choice(f"br {self.f(value)}")
            case _:
                raise NotImplementedError(f"Unhandled architecture: {self.arch.name}")

    def hl_put(
        self,
        ctx: ImmediateMutationContext,
        selected_scratch: RegisterDef,
    ) -> FluidSegment:
        """High-level immediate put into register."""
        factor_result = self._factor_imm(ctx)
        factor_op_choices = tuple(
            self._factor_clause_to_choice(clause, ctx.dest, selected_scratch)
            for clause in factor_result.clauses
        )
        return self.segment(*factor_op_choices)

    def ll_put(self, dest: RegisterDef, src: RegType | ImmType) -> Choice:
        return self.choice(
            self.mov(dest, src), self.segment(self.xor(dest, dest), self.add(dest, src))
        )

    def _factor_clause_to_choice(
        self, clause: FactorClause, dest: RegisterDef, scratch: RegisterDef
    ) -> Choice:
        """Convert a factor clause to corresponding instructions."""
        imm = clause.operand

        match clause.operation:
            case FactorOperation.Init:
                return self.ll_put(dest, imm)
            case FactorOperation.Sub:
                return self.choice(
                    self.sub(dest, imm),
                    self.segment(
                        self.ll_put(scratch, imm),
                        self.sub(dest, scratch),
                    ),
                )
            case FactorOperation.Add:
                return self.choice(
                    self.add(dest, imm),
                    self.segment(
                        self.ll_put(scratch, imm),
                        self.add(
                            dest,
                            scratch,
                        ),
                    ),
                )
            case FactorOperation.Xor:
                return self.choice(
                    self.xor(dest, imm),
                    self.segment(
                        self.ll_put(scratch, imm),
                        self.xor(
                            dest,
                            scratch,
                        ),
                    ),
                )
            case FactorOperation.Neg:
                raise NotImplementedError("Negation support not yet implemented")

    def _factor_imm(
        self,
        ctx: ImmediateMutationContext,
    ) -> FactorResult:
        width = ctx.dest.bit_size
        allow_overflow = width == self.arch.bit_size
        factor_ctx = FactorContext(
            arch=self.arch,
            target=ctx.imm,
            bad_bytes=ctx.bad_bytes,
            allow_overflow=allow_overflow,
            width=width,
            insn_ctx=ctx,
        )
        return compute_factor(factor_ctx)
