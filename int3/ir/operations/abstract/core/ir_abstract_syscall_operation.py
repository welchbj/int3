from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..ir_abstract_operation import IrAbstractOperation

if TYPE_CHECKING:
    from ....variables import IrVar


@dataclass
class IrAbstractSyscallOperation(IrAbstractOperation):
    syscall_num: "IrVar"
    syscall_args: list["IrVar"]
    result: "IrVar"

    def __str__(self) -> str:
        arg_str = ", ".join(str(x) for x in self.syscall_args)
        return f"syscall {self.syscall_num} ({arg_str}) -> {self.result}"
