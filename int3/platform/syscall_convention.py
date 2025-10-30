from dataclasses import dataclass

from int3.architecture import Architecture, Architectures, RegisterDef


@dataclass(frozen=True)
class SyscallConvention:
    """Architecture/platform-specific syscall convention."""

    arch: Architecture
    sys_num: RegisterDef
    result: RegisterDef
    args: tuple[RegisterDef, ...]

    @property
    def max_args(self) -> int:
        """Max number of syscall arguments supported."""
        return len(self.args)

    def llvm_constraint_str(self, num_args: int) -> str:
        """Generate the LLVM inline asm constraint string for a syscall."""
        # LLVM is picky about how registers are prefixed in inline asm constraint strings.
        reg_prefix: str
        match self.arch:
            case Architectures.x86_64.value | Architectures.x86.value:
                reg_prefix = ""
            case Architectures.Mips.value:
                reg_prefix = self.arch.llvm_reg_prefix
            case Architectures.Arm.value | Architectures.Aarch64.value:
                reg_prefix = ""
            case _:
                raise NotImplementedError(
                    f"Linux syscall convention for {self.arch.name} not yet implemented"
                )

        constraint = "={" + reg_prefix + self.result.llvm_name + "}"
        constraint += ",{" + reg_prefix + self.sys_num.llvm_name + "}"
        for idx in range(num_args):
            constraint += ",{" + reg_prefix + self.args[idx].llvm_name + "}"

        return constraint
