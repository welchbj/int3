from abc import ABC, abstractmethod
from contextlib import contextmanager, nullcontext

from int3.errors import Int3SatError
from int3.immediates import BytesImmediate, Immediate, IntImmediate
from int3.registers import Registers, x86_64Registers, x86Registers
from int3.syscalls import SyscallConvention

from .semantic_emitter import SemanticEmitter
from .x86_64emitter import x86_64Emitter
from .x86_emitter import x86Emitter


class LinuxEmitter(SemanticEmitter[Registers], ABC):
    """An emitter for Linux targets (generic with respect to architecture)."""

    @abstractmethod
    def make_syscall_convention(self) -> SyscallConvention[Registers]:
        ...

    def syscall(self, num: int, *args: Registers | Immediate):
        syscall_con = self.make_syscall_convention()
        num_args = len(args)

        @contextmanager
        def _maybe_mov_or_push_syscall_arg(arg_idx: int):
            syscall_reg = syscall_con.reg_args[arg_idx]

            arg_is_used = arg_idx < num_args
            wrapped_cm = (
                self.locked(syscall_reg) if num_args > arg_idx else nullcontext()
            )

            with wrapped_cm:
                if arg_is_used:
                    arg = args[arg_idx]
                    if isinstance(arg, BytesImmediate):
                        self.push_into(dst=syscall_reg, buf=arg)
                    else:
                        self.mov(dst=syscall_reg, src=arg)

                yield

        with _maybe_mov_or_push_syscall_arg(0):
            with _maybe_mov_or_push_syscall_arg(1):
                with _maybe_mov_or_push_syscall_arg(2):
                    with _maybe_mov_or_push_syscall_arg(3):
                        with _maybe_mov_or_push_syscall_arg(4):
                            with _maybe_mov_or_push_syscall_arg(5):
                                self.mov(syscall_con.reg_num, num)
                                self.emit(self.literal_syscall())

    def open(
        self, pathname: Registers | BytesImmediate, flags: Registers | IntImmediate
    ):
        # TODO
        raise Int3SatError("open() unable to find a suitable gadget")

    def close(self, fd: Registers | IntImmediate):
        # TODO
        raise Int3SatError("close() unable to find a suitable gadget")

    def read(
        self,
        fd: Registers | IntImmediate,
        buf: Registers | BytesImmediate,
        count: Registers | IntImmediate,
    ):
        # TODO
        raise Int3SatError("read() unable to find a suitable gadget")

    def write(
        self,
        fd: Registers | IntImmediate,
        buf: Registers | BytesImmediate,
        count: Registers | IntImmediate,
    ):
        # TODO: Dynamic load of syscall number!
        self.syscall(1, fd, buf, count)

    def socket(
        self,
        domain: Registers | IntImmediate,
        type: Registers | IntImmediate,
        protocol: Registers | IntImmediate,
    ):
        # TODO
        raise Int3SatError("socket() unable to find a suitable gadget")

    def connect(
        self,
        fd: Registers | IntImmediate,
        addr: Registers | BytesImmediate,
        addrlen: Registers | IntImmediate,
    ):
        # TODO
        raise Int3SatError("connect() unable to find a suitable gadget")

    def mmap(
        self,
        addr: Registers | IntImmediate,
        length: Registers | IntImmediate,
        prot: Registers | IntImmediate,
        flags: Registers | IntImmediate,
        fd: Registers | IntImmediate,
        offset: Registers | IntImmediate,
    ):
        # TODO
        raise Int3SatError("mmap() unable to find a suitable gadget")

    # TODO: Higher-level networking interface.

    def echo(self, buf: bytes, fd: int = 0, null_terminate: bool = True):
        if null_terminate and not buf.endswith(b"\x00"):
            buf += b"\x00"

        return self.write(fd=fd, buf=buf, count=len(buf))


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
