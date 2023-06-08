import ctypes
import os
import signal
from typing import NoReturn

PROT_READ = 0x1
PROT_WRITE = 0x2
PROT_EXEC = 0x4
PROT_RWX = PROT_READ | PROT_WRITE | PROT_EXEC

MAP_ANON = 0x20
MAP_PRIVATE = 0x2

NULL = 0

_libc = ctypes.CDLL("libc.so.6")

# See: https://man7.org/linux/man-pages/man2/mmap.2.html
_libc.mmap.restype = ctypes.c_void_p
_libc.mmap.argtypes = (
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_long,
)

# See: https://man7.org/linux/man-pages/man2/signal.2.html
_libc.signal.restype = ctypes.c_void_p
_libc.signal.argtypes = (
    ctypes.c_int,
    ctypes.c_void_p,
)


def execute_linux(machine_code: bytes) -> NoReturn:
    # Allocate rwx page(s) of memory.
    rwx_addr = _libc.mmap(
        NULL, len(machine_code), PROT_RWX, MAP_PRIVATE | MAP_ANON, -1, NULL
    )

    # Copy our shellcode into the rwx page(s).
    ctypes.memmove(rwx_addr, machine_code, len(machine_code))

    # Set a SIGUSR1 signal handler to point at the rwx region and trigger
    # redirection of the execution flow there.
    _libc.signal(signal.SIGUSR1, rwx_addr)
    os.kill(os.getpid(), signal.SIGUSR1)
