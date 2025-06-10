import random

import pytest

from int3 import Architecture, Compiler, LinuxCompiler

from .qemu import parametrize_qemu_arch, run_in_qemu


@parametrize_qemu_arch
def test_sys_exit(arch: Architecture):
    cc: LinuxCompiler = Compiler.from_str(f"linux/{arch.name}")

    with cc.def_func.main():
        exit_code = cc.i(0xDEAD)
        exit_code += 0xBEEF
        cc.sys_exit(exit_code)

    qemu_result = run_in_qemu(cc, strace=True)
    lines = qemu_result.log.splitlines()

    # Ensure our custom exit code was observed.
    assert f"exit({0xDEAD + 0xBEEF})" in lines[-1]


@parametrize_qemu_arch
@pytest.mark.parametrize("bytes_len", [1, 2, 3, 7, 8, 9, 15, 65])
def test_sys_write_with_varying_lengths(arch: Architecture, bytes_len: int):
    cc: LinuxCompiler = Compiler.from_str(f"linux/{arch.name}")

    data = bytes([random.choice(b"abcdef0123456789") for _ in range(bytes_len)])
    with cc.def_func.main():
        msg = cc.b(data)
        num_written = cc.sys_write(fd=1, buf=msg)
        cc.sys_exit(num_written)

    result = run_in_qemu(cc)
    assert result.stdout == data
