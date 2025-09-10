from typing import NoReturn

from int3.platform import Platform

from ._linux import execute_linux
from ._windows import execute_windows


def execute(machine_code: bytes, load_addr: int | None = None) -> NoReturn:
    """Execute machine code on the host machine."""
    match Platform.from_host():
        case Platform.Linux:
            execute_linux(machine_code=machine_code, load_addr=load_addr)
        case Platform.Windows:
            execute_windows(machine_code=machine_code, load_addr=load_addr)
