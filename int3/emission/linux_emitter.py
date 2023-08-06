from abc import ABC, abstractmethod
from contextlib import nullcontext
from dataclasses import dataclass

from int3.errors import Int3SatError
from int3.immediates import BytesImmediate, Immediate
from int3.registers import Registers, x86_64Registers, x86Registers
from int3.syscalls import SyscallConvention

from .semantic_emitter import SemanticEmitter
from .x86_64emitter import x86_64Emitter
from .x86_emitter import x86Emitter


@dataclass
class LinuxEmitter(SemanticEmitter[Registers], ABC):
    """An emitter for Linux targets (generic with respect to architecture)."""

    @abstractmethod
    def make_syscall_convention(self) -> SyscallConvention[Registers]:
        ...

    def syscall(self, num: int, *args: Registers | Immediate):
        syscall_con = self.make_syscall_convention()

        num_args = len(args)

        do_arg0 = num_args > 0
        do_arg1 = num_args > 1
        do_arg2 = num_args > 2
        do_arg3 = num_args > 3
        do_arg4 = num_args > 4
        do_arg5 = num_args > 5

        arg0_cm = self.locked(syscall_con.arg0) if do_arg0 else nullcontext()
        arg1_cm = self.locked(syscall_con.arg1) if do_arg1 else nullcontext()
        arg2_cm = self.locked(syscall_con.arg2) if do_arg2 else nullcontext()
        arg3_cm = self.locked(syscall_con.arg3) if do_arg3 else nullcontext()
        arg4_cm = self.locked(syscall_con.arg4) if do_arg4 else nullcontext()
        arg5_cm = self.locked(syscall_con.arg5) if do_arg5 else nullcontext()

        with arg0_cm:
            self.mov(syscall_con.arg0, args[0]) if do_arg0 else None

            with arg1_cm:
                self.mov(syscall_con.arg1, args[1]) if do_arg1 else None

                with arg2_cm:
                    self.mov(syscall_con.arg2, args[2]) if do_arg2 else None

                    with arg3_cm:
                        self.mov(syscall_con.arg3, args[3]) if do_arg3 else None

                        with arg4_cm:
                            self.mov(syscall_con.arg4, args[4]) if do_arg4 else None

                            with arg5_cm:
                                self.mov(syscall_con.arg5, args[5]) if do_arg4 else None

                                with self.locked(syscall_con.num):
                                    self.mov(syscall_con.num, num)
                                    self.emit(self.literal_syscall())

    def open(self):
        # TODO
        raise Int3SatError("open() unable to find a suitable gadget")

    def close(self):
        # TODO
        raise Int3SatError("close() unable to find a suitable gadget")

    def read(self):
        # TODO
        raise Int3SatError("read() unable to find a suitable gadget")

    def write(self):
        # TODO
        raise Int3SatError("write() unable to find a suitable gadget")

    def echo(self, buf: Registers | BytesImmediate, fd: int = 0):
        # TODO
        raise Int3SatError("echo() unable to find a suitable gadget")

    def socket(self):
        # TODO
        raise Int3SatError("socket() unable to find a suitable gadget")

    def connect(self):
        # TODO
        raise Int3SatError("connect() unable to find a suitable gadget")

    def mmap(self):
        # TODO
        raise Int3SatError("mmap() unable to find a suitable gadget")


class Linuxx86Emitter(x86Emitter, LinuxEmitter[x86Registers]):
    def make_syscall_convention(self) -> SyscallConvention[x86Registers]:
        return SyscallConvention[x86Registers](
            result="eax",
            num="eax",
            arg0="ebx",
            arg1="ecx",
            arg2="edx",
            arg3="esi",
            arg4="edi",
            arg5="ebp",
        )


class Linuxx86_64Emitter(x86_64Emitter, LinuxEmitter[x86_64Registers]):
    def make_syscall_convention(self) -> SyscallConvention[x86_64Registers]:
        return SyscallConvention[x86_64Registers](
            result="rax",
            num="rax",
            arg0="rdi",
            arg1="rsi",
            arg2="rdx",
            arg3="r10",
            arg4="r8",
            arg5="r9",
        )
