from __future__ import annotations

import logging
import textwrap
from dataclasses import dataclass, field
from typing import Iterator

from int3.architecture import Architecture, Architectures, RegisterDef
from int3.assembly import assemble
from int3.errors import Int3CodeGenerationError, Int3WrappedKeystoneError
from int3.factor import (
    FactorClause,
    FactorContext,
    FactorOperation,
    FactorResult,
    compute_factor,
)

type RegType = RegisterDef | str
type ImmType = int


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AsmGadget:
    """An assembly gadget."""

    text: str
    bytes: bytes
    len: int = field(init=False)

    def __post_init__(self):
        unindented_text = "\n".join(
            line.strip()
            for line in textwrap.dedent(self.text).splitlines()
            if line.strip()
        )
        logger.debug("Created gadget for the following assembly:")
        for line in textwrap.indent(unindented_text, prefix="    ").splitlines():
            logger.debug(line)

        object.__setattr__(self, "text", unindented_text)
        object.__setattr__(self, "len", len(self.bytes))

    def __str__(self) -> str:
        return self.text


@dataclass(frozen=True)
class CodeGenerator:
    """Common interface for emitting architecture-specific assembly."""
    arch: "Architecture"

    def gadget(self, asm: str) -> AsmGadget:
        return AsmGadget(text=asm, bytes=self.assemble(asm))

    def assemble(self, asm: str) -> bytes:
        return assemble(self.arch, asm)

    def f(self, value: RegType | ImmType) -> str:
        """Format a register or immediate into a Keystone-consumable form."""
        if isinstance(value, str):
            value = self.arch.reg(value)

        if isinstance(value, RegisterDef):
            return f"{self.arch.keystone_reg_prefix}{value}"
        else:
            return f"{value:#x}"

    def nop_pad(self, pad_len: int) -> bytes:
        nop_bytes = self.gadget("nop").bytes
        if pad_len % len(nop_bytes):
            raise Int3CodeGenerationError(
                f"Attempted to pad to misaligned length {pad_len:#x}"
            )

        num_repeats = pad_len // len(nop_bytes)
        return nop_bytes * num_repeats

    def syscall(self, value: ImmType | None = None) -> AsmGadget:
        if value is None:
            return self.gadget("syscall")
        else:
            return self.gadget(f"syscall {self.f(value)}")

    def breakpoint(self) -> AsmGadget:
        match self.arch:
            case Architectures.x86_64.value | Architectures.x86.value:
                return self.gadget("int3")
            case Architectures.Mips.value:
                return self.gadget("break")
            case _:
                raise NotImplementedError(f"Unhandled architecture: {self.arch.name}")

    def inc(self, reg: RegType) -> AsmGadget:
        match self.arch:
            case Architectures.x86_64.value | Architectures.x86.value:
                return self.gadget(f"inc {self.f(reg)}")
            case Architectures.Mips.value:
                return self.gadget(f"addi {self.f(reg)}, 0x1")
            case _:
                raise NotImplementedError(f"Unhandled architecture: {self.arch.name}")

    def xor(self, one: RegType, two: ImmType | RegType) -> AsmGadget:
        return self.gadget(f"xor {self.f(one)}, {self.f(two)}")

    def add(self, one: RegType, two: ImmType | RegType) -> AsmGadget:
        return self.gadget(f"add {self.f(one)}, {self.f(two)}")

    def sub(self, one: RegType, two: ImmType | RegType) -> AsmGadget:
        return self.gadget(f"sub {self.f(one)}, {self.f(two)}")

    def mov(self, one: RegType, two: ImmType | RegType) -> AsmGadget:
        match self.arch:
            case Architectures.x86_64.value | Architectures.x86.value:
                return self.gadget(f"mov {self.f(one)}, {self.f(two)}")
            case Architectures.Mips.value:
                if isinstance(two, int):
                    return self.gadget(f"li {self.f(one)}, {self.f(two)}")
                else:
                    return self.gadget(f"move {self.f(one)}, {self.f(two)}")
            case _:
                raise NotImplementedError(f"Unhandled architecture: {self.arch.name}")

    def compute_pc(self, result: RegType) -> AsmGadget:
        """Compute the program counter for the instruction following this gadget."""
        match self.arch:
            case Architectures.x86_64.value:
                return self.gadget(f"lea {self.f(result)}, [rip]")
            case Architectures.Mips.value:
                raise Int3CodeGenerationError(
                    "Mips does not support fine-grained PC-relative addressing"
                )
            case _:
                raise NotImplementedError(f"Unhandled architecture: {self.arch.name}")

    def jump(self, value: ImmType | RegType) -> AsmGadget:
        match self.arch:
            case Architectures.x86.value:
                return self.gadget(f"jmp {self.f(value)}")
            case Architectures.x86_64.value:
                # See: https://www.felixcloutier.com/x86/jmp
                return self.gadget(f"jmp {self.f(value)}")
            case Architectures.Mips.value:
                if isinstance(value, int):
                    return self.gadget(f"j {self.f(value)}")
                else:
                    return self.gadget(f"jr {self.f(value)}")
            case _:
                raise NotImplementedError(f"Unhandled architecture: {self.arch.name}")

    def hl_put(
        self,
        dest: RegType,
        value: ImmType,
        scratch: RegisterDef,
        bad_bytes: bytes = b"",
    ) -> tuple[AsmGadget, ...]:
        if isinstance(dest, str):
            dest = self.arch.reg(dest)

        factor_result = self._factor_imm(
            value, width=dest.bit_size, bad_bytes=bad_bytes
        )

        gadget_sequence: list[AsmGadget] = []
        for clause in factor_result.clauses:
            asm_candidates = list(self._factor_clause_to_asm(clause, dest, scratch))
            if not asm_candidates:
                raise Int3CodeGenerationError("Unable to generate any factor clauses")

            for asm_candidate in asm_candidates:
                asm_candidate_raw = b"".join(gadget.bytes for gadget in asm_candidate)
                if not any(b in asm_candidate_raw for b in bad_bytes):
                    gadget_sequence.extend(asm_candidate)
                    break
            else:
                raise Int3CodeGenerationError("Unable to generate clean factor clauses")

        return tuple(gadget_sequence)

    def hl_clear(self, dest: RegType) -> AsmGadget:
        # TODO
        raise NotImplementedError("hl_clear not yet implemented")

    def ll_put(self, dest: RegisterDef, imm: int) -> Iterator[tuple[AsmGadget, ...]]:
        yield (self.mov(dest, imm),)

        try:
            yield self.xor(dest, dest), self.add(dest, imm)
        except Int3WrappedKeystoneError:
            pass

    def _factor_clause_to_asm(
        self, clause: FactorClause, dest: RegisterDef, scratch: RegisterDef
    ) -> Iterator[tuple[AsmGadget, ...]]:
        imm = clause.operand

        match clause.operation:
            case FactorOperation.Init:
                yield from self.ll_put(dest, imm)
            case FactorOperation.Sub:
                try:
                    yield (self.sub(dest, imm),)
                except Int3WrappedKeystoneError:
                    pass

                for gadgets in self.ll_put(scratch, imm):
                    yield *gadgets, self.sub(dest, scratch)
            case FactorOperation.Add:
                try:
                    yield (self.add(dest, imm),)
                except Int3WrappedKeystoneError:
                    pass

                for gadgets in self.ll_put(scratch, imm):
                    yield *gadgets, self.add(dest, scratch)
            case FactorOperation.Xor:
                try:
                    yield (self.xor(dest, imm),)
                except Int3WrappedKeystoneError:
                    pass

                for gadgets in self.ll_put(scratch, imm):
                    yield *gadgets, self.xor(dest, scratch)
            case FactorOperation.Neg:
                raise NotImplementedError("Negation support not yet implemented")

    def _factor_imm(self, imm: int, width: int, bad_bytes: bytes) -> FactorResult:
        allow_overflow = width == self.arch.bit_size
        factor_ctx = FactorContext(
            arch=self.arch,
            target=imm,
            bad_bytes=bad_bytes,
            allow_overflow=allow_overflow,
            width=width,
        )
        return compute_factor(factor_ctx)
