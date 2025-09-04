from typing import NoReturn


def execute_windows(machine_code: bytes, load_addr: int | None = None) -> NoReturn:
    raise NotImplementedError("Windows shellcode execution not yet implemented")
