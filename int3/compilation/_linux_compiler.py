from dataclasses import dataclass, field

from int3.meta import Int3Files
from int3.errors import Int3ArgumentError
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
        self, sys_num: int | IrVar, *args: int | bytes | IrVar, hint: str = ""
    ) -> IrVar:
        syscall_num_var: IrVar
        if isinstance(sys_num, int):
            syscall_num_var = self.as_int_constant(sys_num)
        else:
            syscall_num_var = sys_num

        syscall_arg_vars = []
        for arg in args:
            syscall_arg_var: IrVar

            if isinstance(arg, int):
                syscall_arg_var = self.as_int_constant(arg)
            elif isinstance(arg, bytes):
                syscall_arg_var = self.as_bytes_constant(arg)
            elif isinstance(arg, IrVar):
                syscall_arg_var = arg
            else:
                raise Int3ArgumentError(f"Unsupported syscall arg type: {type(arg)}")

            syscall_arg_vars.append(syscall_arg_var)

        syscall_result_var = self.make_native_int_var()

        syscall_bb = self.spawn_bb(new_scope=True, label_hint=f"sys_{hint}")
        syscall_bb.add_operation(
            IrAbstractSyscallOperation(
                syscall_num=syscall_num_var,
                syscall_args=syscall_arg_vars,
                result=syscall_result_var,
            )
        )

        syscall_bb.add_incoming_edge(self.active_bb)

        return syscall_result_var

    def sys_exit(self, status: int | IrVar) -> IrVar:
        return self.syscall(self.sys_nums.exit, status, hint="exit")

    def sys_execve(self, pathname: bytes | IrVar) -> IrVar:
        # TODO: How to annotate argv and envp style arguments?
        return self.syscall(self.sys_nums.execve, pathname, 0, 0, hint="execve")

    def sys_dup2(self, oldfd: int | IrVar, newfd: int | IrVar) -> IrVar:
        return self.syscall(self.sys_nums.dup2, oldfd, newfd, hint="dup2")
