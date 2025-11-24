from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from int3.architecture import Architecture, Architectures, RegisterDef
from int3.errors import (
    Int3CodeGenerationError,
    Int3WrappedCapstoneError,
    Int3WrappedKeystoneError,
)
from int3.factor import (
    FactorClause,
    FactorContext,
    FactorOperation,
    FactorResult,
    ImmediateMutationContext,
    compute_factor,
)

from .choice import Choice, FluidSegment, Option
from .instruction import RegisterListOperand
from .segment import Segment

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
        """Assemble a series of instructions into a Choice instance."""
        parsed_options: list[Option] = []
        parsed_option: Option
        for option in options:
            if isinstance(option, str):
                try:
                    parsed_option = Segment.from_asm(self.triple, option)
                except Int3WrappedKeystoneError as e:
                    logger.debug(f"from_asm failed for {option}: {e}")
                    continue
            elif isinstance(option, bytes):
                try:
                    parsed_option = Segment.from_bytes(self.triple, option)
                except Int3WrappedCapstoneError as e:
                    logger.debug(f"from_bytes failed for {option!r}: {e}")
                    continue
            else:
                parsed_option = option
            parsed_options.append(parsed_option)

        return Choice(tuple(parsed_options))

    def empty(self) -> Choice:
        """Alias for returning a path with no choices."""
        return self.choice()

    def repeat(self, option: Option, num: int) -> FluidSegment:
        """Repeat an option a specified number of times"""
        choice = self.choice(option)
        return FluidSegment(tuple(choice for _ in range(num)))

    def segment(self, *steps: str | bytes | Option) -> FluidSegment:
        parsed_steps: list[Choice | FluidSegment] = []
        for step in steps:
            if isinstance(step, (Choice, FluidSegment)):
                choice = step
            else:
                choice = self.choice(step)
            parsed_steps.append(choice)

        return FluidSegment(tuple(parsed_steps))

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

    def inline(self, mnemonic: str, *operands: RegType | ImmType) -> Choice:
        """Emit a choice for an inline, raw assembly instruction"""
        operands_str = ", ".join(self.f(operand) for operand in operands)
        return self.choice(f"{mnemonic} {operands_str}")

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

    def lsl(self, one: RegType, two: ImmType | RegType) -> Choice:
        """Logical shift left."""
        match self.arch:
            case Architectures.x86_64.value | Architectures.x86.value:
                return self.choice(f"shl {self.f(one)}, {self.f(two)}")
            case Architectures.Mips.value:
                return self.choice(f"sll {self.f(one)}, {self.f(one)}, {self.f(two)}")
            case Architectures.Arm.value | Architectures.Aarch64.value:
                return self.choice(f"lsl {self.f(one)}, {self.f(one)}, {self.f(two)}")
            case _:
                raise NotImplementedError(f"Unhandled architecture: {self.arch.name}")

    def lsr(self, one: RegType, two: ImmType | RegType) -> Choice:
        """Logical shift right."""
        match self.arch:
            case Architectures.x86_64.value | Architectures.x86.value:
                return self.choice(f"shr {self.f(one)}, {self.f(two)}")
            case Architectures.Mips.value:
                return self.choice(f"srl {self.f(one)}, {self.f(one)}, {self.f(two)}")
            case Architectures.Arm.value | Architectures.Aarch64.value:
                return self.choice(f"lsr {self.f(one)}, {self.f(one)}, {self.f(two)}")
            case _:
                raise NotImplementedError(f"Unhandled architecture: {self.arch.name}")

    def mvn(self, dest: RegType, src: RegType) -> Choice:
        """Bitwise NOT (move negated)."""
        match self.arch:
            case Architectures.x86_64.value | Architectures.x86.value:
                # x86 'not' is single-operand, so we need mov + not if dest != src
                if self.f(dest) == self.f(src):
                    return self.choice(f"not {self.f(dest)}")
                else:
                    return self.choice(
                        self.segment(
                            f"mov {self.f(dest)}, {self.f(src)}",
                            f"not {self.f(dest)}",
                        )
                    )
            case Architectures.Mips.value:
                return self.choice(f"not {self.f(dest)}, {self.f(src)}")
            case Architectures.Arm.value | Architectures.Aarch64.value:
                return self.choice(f"mvn {self.f(dest)}, {self.f(src)}")
            case _:
                raise NotImplementedError(f"Unhandled architecture: {self.arch.name}")

    def push(self, *regs: RegType) -> Choice:
        if not regs:
            raise Int3CodeGenerationError("Need at least one register for push")

        match self.arch:
            case Architectures.x86_64.value | Architectures.x86.value:
                if len(regs) != 1:
                    raise Int3CodeGenerationError(
                        "push on x86 families only suppots one register"
                    )

                return self.choice(f"push {self.f(regs[0])}")
            case Architectures.Mips.value:
                if len(regs) != 1:
                    raise Int3CodeGenerationError(
                        "push on Mips only supports one register"
                    )

                sp = self.arch.reg("sp")
                return self.choice(
                    self.segment(
                        f"addi {self.f(sp)}, {self.f(sp)}, -4",
                        f"sw {self.f(regs[0])}, 0({self.f(sp)})",
                    ),
                )
            case Architectures.Arm.value:
                reg_list = RegisterListOperand.of(self.arch, *regs)
                return self.choice(f"push {reg_list}")
            case Architectures.Aarch64.value:
                if len(regs) != 1:
                    raise Int3CodeGenerationError(
                        "push on Aarch64 only supports one register"
                    )

                sp = self.arch.reg("sp")
                return self.choice(f"str {self.f(regs[0])}, [{self.f(sp)}, #-16]!")
            case _:
                raise NotImplementedError(f"Unhandled architecture: {self.arch.name}")

    def pop(self, *regs: RegType) -> Choice:
        if not regs:
            raise Int3CodeGenerationError("Need at least one register for pop")

        match self.arch:
            case Architectures.x86_64.value | Architectures.x86.value:
                if len(regs) != 1:
                    raise Int3CodeGenerationError(
                        "pop on x86 families only suppots one register"
                    )

                return self.choice(f"pop {self.f(regs[0])}")
            case Architectures.Mips.value:
                if len(regs) != 1:
                    raise Int3CodeGenerationError(
                        "pop on Mips only supports one register"
                    )

                sp = self.arch.reg("sp")
                return self.choice(
                    self.segment(
                        f"lw {self.f(regs[0])}, 0({self.f(sp)})",
                        f"addi {self.f(sp)}, {self.f(sp)}, 4",
                    ),
                )
            case Architectures.Arm.value:
                reg_list = RegisterListOperand.of(self.arch, *regs)
                return self.choice(f"pop {reg_list}")
            case Architectures.Aarch64.value:
                if len(regs) != 1:
                    raise Int3CodeGenerationError(
                        "pop on Aarch64 only supports one register"
                    )

                sp = self.arch.reg("sp")
                return self.choice(f"ldr {self.f(regs[0])}, [{self.f(sp)}], #16")
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
                return self.empty()
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

    def store(
        self,
        src: RegType,
        base: RegType,
        offset: int = 0,
        writeback: bool = False,
    ) -> Choice:
        """Store register to memory at [base + offset].

        With ``writeback=True``, uses pre-indexed addressing: stores at
        ``base + offset``, then updates ``base = base + offset``. Only
        supported on ARM/AArch64.

        """
        match self.arch:
            case Architectures.Arm.value | Architectures.Aarch64.value:
                if writeback:
                    return self.choice(
                        f"str {self.f(src)}, [{self.f(base)}, #{offset}]!"
                    )
                else:
                    return self.choice(
                        f"str {self.f(src)}, [{self.f(base)}, #{offset}]"
                    )
            case Architectures.x86.value | Architectures.x86_64.value:
                if writeback:
                    raise Int3CodeGenerationError("x86 does not support writeback")

                return self.choice(f"mov [{self.f(base)} {offset:+}], {self.f(src)}")
            case Architectures.Mips.value:
                if writeback:
                    raise Int3CodeGenerationError("MIPS does not support writeback")

                return self.choice(f"sw {self.f(src)}, {offset}({self.f(base)})")
            case _:
                raise NotImplementedError(f"Unhandled architecture: {self.arch.name}")

    def load(
        self,
        dest: RegType,
        base: RegType,
        offset: int = 0,
        writeback: bool = False,
    ) -> Choice:
        """Load register from memory.

        Without writeback, loads from ``[base + offset]``.

        With ``writeback=True``, uses post-indexed addressing: loads from
        ``base``, then updates ``base = base + offset``. Only supported on
        ARM/AArch64.

        """
        match self.arch:
            case Architectures.Arm.value | Architectures.Aarch64.value:
                if writeback:
                    return self.choice(
                        f"ldr {self.f(dest)}, [{self.f(base)}], #{offset}"
                    )
                else:
                    return self.choice(
                        f"ldr {self.f(dest)}, [{self.f(base)}, #{offset}]"
                    )
            case Architectures.x86.value | Architectures.x86_64.value:
                if writeback:
                    raise Int3CodeGenerationError("x86 does not support writeback")

                return self.choice(f"mov {self.f(dest)}, [{self.f(base)} {offset:+}]")
            case Architectures.Mips.value:
                if writeback:
                    raise Int3CodeGenerationError("MIPS does not support writeback")

                return self.choice(f"lw {self.f(dest)}, {offset}({self.f(base)})")
            case _:
                raise NotImplementedError(f"Unhandled architecture: {self.arch.name}")

    def ll_clear(self, dest: RegisterDef) -> Choice:
        """Clear a register."""
        # TODO: Incorporate zero register options.

        return self.choice(
            self.xor(dest, dest),
            self.sub(dest, dest),
            self.mov(dest, 0),
        )

    def ll_put(self, dest: RegisterDef, src: RegType | ImmType) -> Choice:
        # TODO: Incorporate zero register options.

        options: list[Choice | FluidSegment] = [
            self.mov(dest, src),
            self.segment(
                self.ll_clear(dest),
                self.choice(
                    self.add(dest, src),
                    self.xor(dest, src),
                ),
            ),
        ]

        if not isinstance(src, int):
            options.append(
                self.segment(
                    self.push(src),
                    self.pop(dest),
                )
            )

            # ARM: multi-register push/pop stack transfer patterns.
            # These provide alternative encodings that can avoid null bytes
            # when transferring between low (r0-r7) and high (r8+) registers.
            if self.arch == Architectures.Arm.value:
                options.extend(self._arm_stack_transfer_options(dest, src))

        # For small (2^n - 1) immediates like 1, 3, 7, etc., use clear+not+lsr.
        # This provides an alternative encoding that may avoid bad bytes.
        if isinstance(src, int):
            for n in range(1, 17):
                if src == (1 << n) - 1:
                    shift = dest.bit_size - n
                    options.append(
                        self.segment(
                            self.ll_clear(dest),
                            self.mvn(dest, dest),
                            self.lsr(dest, shift),
                        )
                    )
                    break

        return self.choice(*options)

    def _arm_stack_transfer_options(
        self, dest: RegisterDef, src: RegType
    ) -> list[FluidSegment]:
        """ARM-specific stack transfer options using multi-register push/pop.

        ARM's multi-register push/pop instructions use a bitmap encoding that
        can avoid null bytes in certain register combinations. This provides
        two transfer patterns:

        1. High-to-low transfer (e.g., r8 -> r0):
           str src, [sp, #-4]!   ; push src value
           str src, [sp, #-4]!   ; push src value again (fills both pop slots)
           pop {dest, src}       ; dest gets src's value, src restored

        2. Low-to-high transfer (e.g., r0 -> r8):
           push {src, dest}      ; save src to stack
           ldr dest, [sp], #8    ; dest = src's value, restore sp

        Both patterns are offered as alternatives; the Choice system selects
        the one without bad bytes based on the specific register combination.
        """
        if isinstance(src, str):
            src = self.arch.reg(src)

        sp = self.arch.reg("sp")

        return [
            # Pattern 1: High-to-low transfer via double store + multi-reg pop
            self.segment(
                self.store(src, sp, offset=-4, writeback=True),
                self.store(src, sp, offset=-4, writeback=True),
                self.pop(dest, src),
            ),
            # Pattern 2: Low-to-high transfer via multi-reg push + load
            self.segment(
                self.push(dest, src),
                self.load(dest, sp, offset=8, writeback=True),
            ),
        ]

    def hl_put_imm(
        self,
        imm: int,
        dest: RegisterDef,
        scratch_regs: tuple[RegisterDef, ...],
        bad_bytes: bytes,
    ) -> Choice:
        """High-level choices to put an immediate value into a register."""

        options = []

        # The simplest approach is to load the immediate value directly into the
        # destination register, without using a transitory register.
        direct_imm_ctx = ImmediateMutationContext(
            arch=self.arch,
            bad_bytes=bad_bytes,
            imm=imm,
            dest=dest,
            scratch_regs=scratch_regs,
        )
        for scratch_reg in scratch_regs:
            try:
                options.append(self._hl_put_imm_direct(direct_imm_ctx, scratch_reg))
            except Int3CodeGenerationError as e:
                logger.debug(f"High-level put direct approach failed: {e}")
                continue

        # We also go one level deeper by attempting to load the desired immediate
        # value into a transitory intermediate register, which we then move into
        # the final destination register.
        for intermediate_reg in scratch_regs:
            remaining_scratch_regs = tuple(
                r for r in scratch_regs if r != intermediate_reg
            )
            if not remaining_scratch_regs:
                continue

            indirect_imm_ctx = ImmediateMutationContext(
                arch=self.arch,
                bad_bytes=bad_bytes,
                imm=imm,
                dest=intermediate_reg,
                scratch_regs=remaining_scratch_regs,
            )
            for scratch_reg in remaining_scratch_regs:
                try:
                    load_segment = self._hl_put_imm_direct(
                        indirect_imm_ctx, scratch_reg
                    )
                    full_segment = self.segment(
                        load_segment,
                        self.ll_put(dest, intermediate_reg),
                    )
                    options.append(full_segment)
                except Int3CodeGenerationError as e:
                    logger.debug(
                        f"High-level put indirect approach with intermediate "
                        f"reg {intermediate_reg} failed: {e}"
                    )
                    continue

        if not options:
            raise Int3CodeGenerationError(
                f"Unable to generate clean code to load {imm:#x} into {dest}"
            )
        return self.choice(*options)

    def _hl_put_imm_direct(
        self,
        ctx: ImmediateMutationContext,
        selected_scratch: RegisterDef,
    ) -> FluidSegment:
        factor_result = self._factor_imm(ctx)
        factor_op_choices = tuple(
            self._factor_clause_to_choice(clause, ctx.dest, selected_scratch)
            for clause in factor_result.clauses
        )
        return self.segment(*factor_op_choices)

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
            imm_mut_ctx=ctx,
        )
        return compute_factor(factor_ctx)
