from int3 import Compiler, LinuxCompiler
from int3.architecture import Architecture

from .qemu import parametrize_qemu_arch, run_in_qemu


def test_not_defining_an_entrypoint():
    cc = Compiler.from_host()

    # TODO

    assert False


def test_custom_entrypoint():
    # TODO
    assert False


def test_non_void_entrypoint():
    # TODO
    assert False


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
