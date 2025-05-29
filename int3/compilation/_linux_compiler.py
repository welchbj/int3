from dataclasses import dataclass, field

from int3.errors import Int3ArgumentError
from int3.ir import (
    AnyIrType,
    IrBytesType,
    IrIntConstant,
    IrIntType,
    IrIntVariable,
    IrOperation,
    IrOperator,
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
        sys_num: int | IrIntType,
        *args: int | bytes | IrIntType | IrBytesType,
        hint: str = "",
    ) -> IrIntVariable:
        syscall_num_var: IrIntVariable | IrIntConstant
        if isinstance(sys_num, int):
            syscall_num_var = self.i(sys_num)
        else:
            syscall_num_var = sys_num

        syscall_arg_vars: list[AnyIrType] = [syscall_num_var]
        for arg in args:
            syscall_arg_var: IrIntVariable | IrIntConstant

            if isinstance(arg, int):
                syscall_arg_var = self.i(arg)
            elif isinstance(arg, bytes):
                raise NotImplementedError("syscall bytes() arguments still WIP")
            elif isinstance(arg, IrIntVariable):
                syscall_arg_var = arg
            else:
                raise Int3ArgumentError(f"Unsupported syscall arg type: {type(arg)}")

            syscall_arg_vars.append(syscall_arg_var)

        syscall_result_var = self.i()
        # TODO: We should emit Lock instructions to enforce the calling convention.
        self.add_operation(
            IrOperation(
                operator=IrOperator.Syscall,
                result=syscall_result_var,
                args=syscall_arg_vars,
            )
        )
        return syscall_result_var

    def sys_exit(self, status: int | IrIntType) -> IrIntVariable:
        return self.syscall(self.sys_nums.exit, status, hint="exit")

    def sys_write(
        self,
        fd: int | IrIntType,
        buf: int | IrIntType | IrBytesType,
        count: int | IrIntType,
    ) -> IrIntVariable:
        # TODO: Utility options for automatically deriving the length and appending a null terminator.
        return self.syscall(self.sys_nums.write, fd, buf, count, hint="write")

    def sys_execve(self, pathname: bytes | IrBytesType) -> IrIntVariable:
        # TODO: How to annotate argv and envp style arguments?
        return self.syscall(self.sys_nums.execve, pathname, 0, 0, hint="execve")

    def sys_dup2(self, oldfd: int | IrIntType, newfd: int | IrIntType) -> IrIntVariable:
        return self.syscall(self.sys_nums.dup2, oldfd, newfd, hint="dup2")
