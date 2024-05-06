from dataclasses import dataclass, field

from int3.constants import Int3Files
from int3.ir.variables import IrVar

from ..compiler import Compiler
from .syscalls import LinuxSyscallNumbers


@dataclass
class LinuxSyscallInterfaceMixin(Compiler):
    sys_nums: LinuxSyscallNumbers = field(init=False)

    def __post_init__(self):
        self.sys_nums = LinuxSyscallNumbers(
            Int3Files.SyscallTablesDir / f"syscalls-{self.arch_meta.linux_kernel_name}"
        )

    def syscall(self, sys_num: int | IrVar, *args: int | bytes | IrVar) -> IrVar:
        # TODO
        pass
