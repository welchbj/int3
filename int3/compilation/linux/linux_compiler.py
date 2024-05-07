from dataclasses import dataclass

from ._linux_high_level_interface_mixin import LinuxHighLevelInterfaceMixin
from ._linux_syscall_interface_mixin import LinuxSyscallInterfaceMixin


@dataclass
class LinuxCompiler(LinuxSyscallInterfaceMixin, LinuxHighLevelInterfaceMixin):
    pass
