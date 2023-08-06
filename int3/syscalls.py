from __future__ import annotations

from dataclasses import dataclass
from typing import Generic

from int3.registers import Registers


@dataclass(frozen=True)
class SyscallConvention(Generic[Registers]):
    result: Registers
    num: Registers
    arg0: Registers
    arg1: Registers
    arg2: Registers
    arg3: Registers
    arg4: Registers
    arg5: Registers
