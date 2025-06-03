from dataclasses import dataclass, field

from int3.errors import Int3ArgumentError
from int3.meta import Int3Files
from int3.platform import LinuxSyscallNumbers

from .compiler import Compiler
from .types import ArgType, IntArgType, IntVariable


@dataclass
class LinuxCompiler(Compiler):
    sys_nums: LinuxSyscallNumbers = field(init=False)

    def __post_init__(self):
        super().__post_init__()

        self.sys_nums = LinuxSyscallNumbers(
            Int3Files.SyscallTablesDir / f"syscalls-{self.arch.linux_kernel_name}"
        )

    def syscall(
        self,
        sys_num: IntArgType,
        *args: ArgType,
        hint: str = "",
    ) -> IntVariable:
        # TODO
        return self.add(0xDEAD, 0xBEEF)

    def sys_exit(self, status: IntArgType) -> IntVariable:
        return self.syscall(self.sys_nums.exit, status, hint="exit")

    def sys_write(
        self,
        fd: IntArgType,
        buf: IntArgType,
        count: IntArgType,
    ) -> IntVariable:
        # TODO: Utility options for automatically deriving the length and appending a null terminator.
        return self.syscall(self.sys_nums.write, fd, buf, count, hint="write")

    def sys_dup2(self, oldfd: IntArgType, newfd: IntArgType) -> IntVariable:
        return self.syscall(self.sys_nums.dup2, oldfd, newfd, hint="dup2")
