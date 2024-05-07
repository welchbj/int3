from dataclasses import dataclass, field

from int3.constants import Int3Files
from int3.ir import IrIntConstant, IrVar

from ..compiler import Compiler
from .syscalls import LinuxSyscallNumbers


@dataclass
class LinuxSyscallInterfaceMixin(Compiler):
    sys_nums: LinuxSyscallNumbers = field(init=False)

    def __post_init__(self):
        super().__post_init__()

        self.sys_nums = LinuxSyscallNumbers(
            Int3Files.SyscallTablesDir / f"syscalls-{self.arch_meta.linux_kernel_name}"
        )

    def syscall(self, sys_num: int | IrVar, *args: int | bytes | IrVar) -> IrVar:
        # TODO
        return IrIntConstant.i32(-1)

    def sys_exit(self, status: int | IrVar) -> IrVar:
        return self.syscall(self.sys_nums.exit, status)

    def sys_execve(self, pathname: bytes | IrVar) -> IrVar:
        # TODO: How to annotate argv and envp style arguments?
        return self.syscall(self.sys_nums.execve, pathname, 0, 0)

    def sys_dup2(self, oldfd: int | IrVar, newfd: int | IrVar) -> IrVar:
        return self.syscall(self.sys_nums.dup2, oldfd, newfd)
