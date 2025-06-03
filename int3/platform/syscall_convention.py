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
