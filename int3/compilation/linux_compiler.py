from dataclasses import dataclass, field

from int3._vendored.llvmlite import ir as llvmir
from int3.errors import Int3CompilationError
from int3.meta import Int3Files
from int3.platform import LinuxSyscallNumbers

from .compiler import Compiler
from .types import (
    BytesPointer,
    IntVariable,
    PyArgType,
    PyIntArgType,
    PyIntValueType,
)


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
        sys_num: PyIntArgType,
        *args: PyArgType,
        hint: str = "",
    ) -> IntVariable:
        """Emit a syscall instruction for the specified set of arguments."""

        combined_args: list[PyIntValueType] = []

        # Coerce all arguments to be of the native unsigned int.
        combined_args.append(self.coerce_to_type(sys_num, self.types.unat))
        combined_args.extend(
            [self.coerce_to_type(arg, self.types.unat) for arg in args]
        )

        # Create llvmlite FunctionType.
        llvm_func_type = llvmir.FunctionType(
            return_type=self.types.unat.wrapped_type,
            args=[arg.type.wrapped_type for arg in combined_args],
        )

        # Emit the actual LLVM IR inline assembly.
        self.builder.comment(f"SYS_{hint}")
        res = self.builder.asm(
            ftype=llvm_func_type,
            asm=self.codegen.syscall(),
            constraint=self.syscall_conv.llvm_constraint_str(num_args=len(args)),
            args=[arg.wrapped_llvm_node for arg in combined_args],
            side_effect=True,
        )

        return IntVariable(compiler=self, type=self.types.unat, wrapped_llvm_node=res)

    def sys_exit(self, status: PyIntArgType) -> IntVariable:
        return self.syscall(self.sys_nums.exit, status, hint="exit")

    def sys_write(
        self,
        fd: PyIntArgType,
        buf: PyArgType,
        count: PyIntArgType | None = None,
    ) -> IntVariable:
        if isinstance(buf, bytes):
            buf = self.b(buf)
        elif isinstance(buf, int):
            buf = self.u(buf)

        if count is None:
            if isinstance(buf, BytesPointer):
                count = len(buf)
            else:
                raise Int3CompilationError(
                    f"Unable to derive unspecified count for {buf}"
                )

        return self.syscall(self.sys_nums.write, fd, buf, count, hint="write")

    def sys_dup2(self, oldfd: PyIntArgType, newfd: PyIntArgType) -> IntVariable:
        return self.syscall(self.sys_nums.dup2, oldfd, newfd, hint="dup2")
