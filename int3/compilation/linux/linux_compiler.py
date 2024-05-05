from dataclasses import dataclass

from ..compiler import Compiler
from .linux_syscall_mixin import LinuxSyscallMixin


@dataclass
class LinuxCompiler(Compiler, LinuxSyscallMixin):
    # TODO
    pass
