from dataclasses import dataclass, field

from int3.errors import Int3ArgumentError
from int3.meta import Int3Files
from int3.platform import LinuxSyscallNumbers

from .compiler import Compiler


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
        sys_num: int,
        *args: int | bytes,
        hint: str = "",
    ) -> ...: ...

    def sys_exit(self, status: int) -> ...:
        return self.syscall(self.sys_nums.exit, status, hint="exit")

    def sys_write(
        self,
        fd: int,
        buf: int,
        count: int,
    ) -> ...:
        # TODO: Utility options for automatically deriving the length and appending a null terminator.
        return self.syscall(self.sys_nums.write, fd, buf, count, hint="write")

    def sys_execve(self, pathname: bytes) -> ...:
        # TODO: How to annotate argv and envp style arguments?
        return self.syscall(self.sys_nums.execve, pathname, 0, 0, hint="execve")

    def sys_dup2(self, oldfd: int, newfd: int) -> ...:
        return self.syscall(self.sys_nums.dup2, oldfd, newfd, hint="dup2")
