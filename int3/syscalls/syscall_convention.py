from __future__ import annotations

from dataclasses import dataclass
from typing import Generic

from int3.registers import Registers


@dataclass(frozen=True)
class SyscallConvention(Generic[Registers]):
    reg_result: Registers
    reg_num: Registers
    reg_args: tuple[Registers, ...]
