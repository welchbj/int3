from dataclasses import dataclass, field

from int3.errors import Int3ArgumentError
from int3.ir import (
    HlirAnyType,
    HlirBytesType,
    HlirIntConstant,
    HlirIntType,
    HlirIntVariable,
    HlirOperation,
    HlirOperator,
)
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
        sys_num: int | HlirIntType,
        *args: int | bytes | HlirIntType | HlirBytesType,
        hint: str = "",
    ) -> HlirIntVariable:
        syscall_num_var: HlirIntVariable | HlirIntConstant
        if isinstance(sys_num, int):
            syscall_num_var = self.i(sys_num)
        else:
            syscall_num_var = sys_num

        syscall_arg_vars: list[HlirAnyType] = [syscall_num_var]
        for arg in args:
            syscall_arg_var: HlirIntVariable | HlirIntConstant

            if isinstance(arg, int):
                syscall_arg_var = self.i(arg)
            elif isinstance(arg, bytes):
                raise NotImplementedError("syscall bytes() arguments still WIP")
            elif isinstance(arg, HlirIntVariable):
                syscall_arg_var = arg
            else:
                raise Int3ArgumentError(f"Unsupported syscall arg type: {type(arg)}")

            syscall_arg_vars.append(syscall_arg_var)

        syscall_result_var = self.i()
        # TODO: We should emit Lock instructions to enforce the calling convention.
        self.add_operation(
            HlirOperation(
                operator=HlirOperator.Syscall,
                result=syscall_result_var,
                args=syscall_arg_vars,
            )
        )
        return syscall_result_var

    def sys_exit(self, status: int | HlirIntType) -> HlirIntVariable:
        return self.syscall(self.sys_nums.exit, status, hint="exit")

    def sys_write(
        self,
        fd: int | HlirIntType,
        buf: int | HlirIntType | HlirBytesType,
        count: int | HlirIntType,
    ) -> HlirIntVariable:
        # TODO: Utility options for automatically deriving the length and appending a null terminator.
        return self.syscall(self.sys_nums.write, fd, buf, count, hint="write")

    def sys_execve(self, pathname: bytes | HlirBytesType) -> HlirIntVariable:
        # TODO: How to annotate argv and envp style arguments?
        return self.syscall(self.sys_nums.execve, pathname, 0, 0, hint="execve")

    def sys_dup2(
        self, oldfd: int | HlirIntType, newfd: int | HlirIntType
    ) -> HlirIntVariable:
        return self.syscall(self.sys_nums.dup2, oldfd, newfd, hint="dup2")
