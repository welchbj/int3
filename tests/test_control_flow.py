from typing import cast

import pytest

from int3 import Architecture, Compiler, LinuxCompiler, Int3CodeGenerationError

from .qemu import parametrize_qemu_arch, run_in_qemu


@parametrize_qemu_arch
def test_basic_if_else(arch: Architecture):
    load_addr = 0xFF0000
    cc = Compiler.from_str(f"linux/{arch.name}", load_addr=load_addr)
    cc = cast(LinuxCompiler, cc)

    with cc.def_func.helper():
        with cc.if_else(cc.i(3) < 2) as (if_, else_):
            with if_:
                # Should not be executed.
                cc.sys_exit(1)
            with else_:
                cc.puts(b"Else taken")
                cc.sys_exit(0)

    with cc.def_func.main():
        cc.call.helper()

    qemu_result = run_in_qemu(cc, load_addr=load_addr, strace=True)
    assert "Else taken" in qemu_result.stdout.decode()


def test_detection_of_broken_control_flow():
    cc = Compiler.from_host(bad_bytes=b"\x00")
    cc = cast(LinuxCompiler, cc)

    with cc.def_func.main():
        with cc.if_else(cc.i(1).equals(2)) as (if_, else_):
            with if_:
                cc.sys_exit(1)
            with else_:
                cc.sys_exit(0)

    with pytest.raises(Int3CodeGenerationError):
        cc.compile()
