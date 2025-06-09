import pytest

from int3 import Architecture, Compiler, LinuxCompiler
from int3.errors import Int3CompilationError

from .qemu import parametrize_qemu_arch, run_in_qemu


def test_not_defining_an_entrypoint():
    cc = Compiler.from_host()

    with cc.def_func.not_the_entrypoint():
        ...

    with pytest.raises(Int3CompilationError):
        cc.compile()


def test_non_void_entrypoint():
    cc = Compiler.from_host()

    with cc.def_func.main(int):
        cc.ret(0xCAFE)

    with pytest.raises(Int3CompilationError):
        cc.compile()


@parametrize_qemu_arch
def test_simple_exit(arch: Architecture):
    cc: LinuxCompiler = Compiler.from_str(f"linux/{arch.name}")

    with cc.def_func.main():
        exit_code = cc.i(0xDEAD)
        exit_code += 0xBEEF
        cc.sys_exit(exit_code)

    program = cc.compile()
    qemu_result = run_in_qemu(program, arch=arch, strace=True)
    lines = qemu_result.log.splitlines()

    # Ensure our custom exit code was observed.
    assert f"exit({0xDEAD + 0xBEEF})" in lines[-1]
