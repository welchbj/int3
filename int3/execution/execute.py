from typing import NoReturn

from int3.errors import Int3MissingEntityError
from int3.platforms import Platforms

from ._linux import execute_linux
from ._windows import execute_windows


def execute(machine_code: bytes) -> NoReturn:
    match platform := Platforms.from_host():
        case Platforms.Linux.value:
            execute_linux(machine_code=machine_code)
        case Platforms.Windows.value:
            execute_windows(machine_code=machine_code)
        case _:
            raise Int3MissingEntityError(
                f"No execution support for platform {platform}"
            )
