from __future__ import annotations

from abc import ABC, abstractmethod
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass, field
from typing import Type

from int3.architectures import Architecture, Architectures
from int3.constants import Int3Files
from int3.errors import Int3MissingEntityError
from int3.gadgets import Gadget
from int3.immediates import BytesImmediate, Immediate, IntImmediate
from int3.registers import (
    GpRegisters,
    MipsRegisters,
    Registers,
    x86_64Registers,
    x86Registers,
)
from int3.syscalls import LinuxSyscallNumbers, SyscallConvention

from .mips_emitter import MipsEmitter
from .semantic_emitter import SemanticEmitter
from .x86_64emitter import x86_64Emitter
from .x86_emitter import x86Emitter


@dataclass
class LinuxEmitter(SemanticEmitter[Registers], ABC):
    """An emitter for Linux targets (generic with respect to architecture)."""

    syscall_numbers: LinuxSyscallNumbers = field(init=False)

    @abstractmethod
    def make_syscall_convention(self) -> SyscallConvention[Registers]:
        ...

    @abstractmethod
    def syscall_gadget(self, imm: int = 0) -> Gadget:
        ...

    def __post_init__(self):
        self.syscall_numbers = self._load_syscall_numbers()

    def _load_syscall_numbers(self) -> LinuxSyscallNumbers:
        syscall_table_file_name = f"syscalls-{self.ctx.architecture.linux_kernel_name}"
        syscall_table_path = Int3Files.SYSCALL_TABLES_DIR / syscall_table_file_name
        return LinuxSyscallNumbers(syscall_table_path)

    def syscall(self, num: int, *args: Registers | Immediate) -> Registers:
        syscall_con = self.make_syscall_convention()
        num_args = len(args)

        @contextmanager
        def _maybe_mov_or_push_syscall_arg(arg_idx: int):
            syscall_reg = syscall_con.reg_args[arg_idx]

            # TODO: Maybe need to dynamically find a register for pushing (e.g., mips).

            arg_is_used = arg_idx < num_args
            wrapped_cm = (
                self.locked(syscall_reg) if num_args > arg_idx else nullcontext()
            )

            if arg_is_used:
                arg = args[arg_idx]
                if isinstance(arg, BytesImmediate):
                    self.push_into(dst=syscall_reg, buf=arg)
                else:
                    self.mov(dst=syscall_reg, src=arg)

            with wrapped_cm:
                yield

        # TODO: Need support for potentially passing some arguments on the stack.

        with _maybe_mov_or_push_syscall_arg(0):
            with _maybe_mov_or_push_syscall_arg(1):
                with _maybe_mov_or_push_syscall_arg(2):
                    with _maybe_mov_or_push_syscall_arg(3):
                        with _maybe_mov_or_push_syscall_arg(4):
                            with _maybe_mov_or_push_syscall_arg(5):
                                self.mov(syscall_con.reg_num, num)
                                self.emit(self.syscall_gadget())
                                return syscall_con.reg_result

    def open(
        self,
        pathname: Registers | BytesImmediate,
        flags: Registers | IntImmediate,
        mode: Registers | IntImmediate,
    ) -> Registers:
        return self.syscall(self.syscall_numbers.open, pathname, flags, mode)

    def close(self, fd: Registers | IntImmediate) -> Registers:
        return self.syscall(self.syscall_numbers.close, fd)

    def read(
        self,
        fd: Registers | IntImmediate,
        buf: Registers | BytesImmediate,
        count: Registers | IntImmediate,
    ) -> Registers:
        return self.syscall(self.syscall_numbers.read, fd, buf, count)

    def write(
        self,
        fd: Registers | IntImmediate,
        buf: Registers | BytesImmediate,
        count: Registers | IntImmediate,
    ) -> Registers:
        return self.syscall(self.syscall_numbers.write, fd, buf, count)

    def socket(
        self,
        domain: Registers | IntImmediate,
        type_: Registers | IntImmediate,
        protocol: Registers | IntImmediate,
    ) -> Registers:
        return self.syscall(self.syscall_numbers.socket, domain, type_, protocol)

    def connect(
        self,
        fd: Registers | IntImmediate,
        addr: Registers | BytesImmediate,
        addrlen: Registers | IntImmediate,
    ) -> Registers:
        return self.syscall(self.syscall_numbers.connect, fd, addr, addrlen)

    def mmap(
        self,
        addr: Registers | IntImmediate,
        length: Registers | IntImmediate,
        prot: Registers | IntImmediate,
        flags: Registers | IntImmediate,
        fd: Registers | IntImmediate,
        offset: Registers | IntImmediate,
    ) -> Registers:
        return self.syscall(
            self.syscall_numbers.mmap, addr, length, prot, flags, fd, offset
        )

    def mprotect(
        self,
        addr: Registers | IntImmediate,
        length: Registers | IntImmediate,
        prot: Registers | IntImmediate,
    ) -> Registers:
        return self.syscall(self.syscall_numbers.mprotect, addr, length, prot)

    # TODO: Higher-level networking interface.

    def map_rwx(self, result: GpRegisters | None) -> Registers:
        # TODO
        raise NotImplementedError("map_rwx() not yet implemented")

    def echo(
        self,
        buf: bytes | Registers,
        fd: int | Registers = 0,
        null_terminate: bool = True,
    ):
        if isinstance(buf, bytes) and null_terminate and not buf.endswith(b"\x00"):
            buf += b"\x00"

        return self.write(fd=fd, buf=buf, count=len(buf))

    @staticmethod
    def get_emitter_cls_for_arch(
        arch: Architecture[Registers, GpRegisters]
    ) -> Type[LinuxEmitter[Registers]]:
        match arch:
            case Architectures.x86.value:
                return Linuxx86Emitter
            case Architectures.x86_64.value:
                return Linuxx86_64Emitter
            case Architectures.Mips.value:
                return LinuxMipsEmitter
            case _:
                raise Int3MissingEntityError(
                    f"No LinuxEmitter defined for arch {arch.name}"
                )


class Linuxx86Emitter(x86Emitter, LinuxEmitter[x86Registers]):
    def make_syscall_convention(self) -> SyscallConvention[x86Registers]:
        return SyscallConvention[x86Registers](
            reg_result="eax",
            reg_num="eax",
            reg_args=(
                "ebx",
                "ecx",
                "edx",
                "esi",
                "edi",
                "ebp",
            ),
        )

    def syscall_gadget(self, imm: int = 0) -> Gadget:
        return Gadget("syscall")


class Linuxx86_64Emitter(x86_64Emitter, LinuxEmitter[x86_64Registers]):
    def make_syscall_convention(self) -> SyscallConvention[x86_64Registers]:
        return SyscallConvention[x86_64Registers](
            reg_result="rax",
            reg_num="rax",
            reg_args=(
                "rdi",
                "rsi",
                "rdx",
                "r10",
                "r8",
                "r9",
            ),
        )

    def syscall_gadget(self, imm: int = 0) -> Gadget:
        return Gadget("syscall")


class LinuxMipsEmitter(MipsEmitter, LinuxEmitter[MipsRegisters]):
    def make_syscall_convention(self) -> SyscallConvention[MipsRegisters]:
        return SyscallConvention[MipsRegisters](
            reg_result="$v0",
            reg_num="$v0",
            reg_args=(
                "$a0",
                "$a1",
                "$a2",
                "$a3",
            ),
        )

    def syscall_gadget(self, imm: int = 0) -> Gadget:
        return Gadget(f"syscall {hex(imm)}")
