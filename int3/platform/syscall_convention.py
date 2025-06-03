from dataclasses import dataclass

from int3.architecture import RegisterDef


@dataclass(frozen=True)
class SyscallConvention:
    sys_num: RegisterDef
    result: RegisterDef
    args: tuple[RegisterDef, ...]

    @property
    def max_args(self) -> int:
        return len(self.args)

    def llvm_constraint_str(self, num_args: int) -> str:
        constraint = f"={self.result.name}"

        constraint += f",{self.sys_num.name}"
        for idx in range(num_args):
            constraint += f",{self.args[idx].name}"

        return constraint
