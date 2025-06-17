from typing import NoReturn

from ._linux import execute_linux


def execute(machine_code: bytes, load_addr: int | None = None) -> NoReturn:
    # TODO: Determine host machine type rather than defaulting to Linux.
    execute_linux(machine_code=machine_code, load_addr=load_addr)
