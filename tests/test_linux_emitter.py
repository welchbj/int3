import os
import random
import stat
import tempfile
from pathlib import Path

from int3 import (
    Architecture,
    Context,
    GpRegisters,
    LinuxEmitter,
    Platforms,
    Registers,
    assemble,
)

from .qemu import FilePaths, compile_src, parametrize_qemu_arch, run_in_qemu
from .utils import make_random_word


@parametrize_qemu_arch
def test_linux_emitter_write_to_file(
    arch: Architecture[Registers, GpRegisters], tmp_path: Path
):
    # We add "/" as a bad byte since we know this will be in tmp_path generated
    # paths.
    ctx = Context(architecture=arch, platform=Platforms.Linux.value, bad_bytes=b"\x00/")

    short_word = make_random_word(arch.byte_size - 1)
    aligned_word = make_random_word(arch.byte_size)
    long_word = make_random_word(arch.byte_size * 4)

    for word in [short_word, aligned_word, long_word]:
        emitter = LinuxEmitter.get_emitter(arch, ctx)

        out_file = tmp_path / f"out_{word.decode()}"
        assert not out_file.exists()

        pathname = str(out_file).encode() + b"\x00"

        with emitter.stack_scope(ret=True):
            fd_reg = emitter.open(
                pathname=pathname,
                flags=os.O_RDWR | os.O_CREAT,
                mode=stat.S_IRWXU,
            )
            emitter.echo(word, fd=fd_reg)

        print("\nGenerated assembly:")
        print(str(emitter))

        shellcode = assemble(ctx=ctx, assembly=str(emitter))
        run_in_qemu(shellcode=shellcode, arch=arch)

        assert out_file.read_bytes() == word + b"\x00"


@parametrize_qemu_arch
def test_linux_execve(arch: Architecture[Registers, GpRegisters]):
    with tempfile.NamedTemporaryFile(delete=False) as argv_envp_printer_bin:
        # Compile execve argv/envp printer program before launching shellcode runner.
        compile_src(
            arch=arch,
            in_file=FilePaths.INT3_ARGV_ENVP_PRINTER_SRC,
            out_file=Path(argv_envp_printer_bin.name),
        )

        # Generate random argv.
        argv_len = random.randrange(0x1, 0x10)
        argv = [make_random_word(random.randrange(0x1, 0x20)) for _ in range(argv_len)]

        # Generate random envp.
        envp_len = random.randrange(0x1, 0x10)
        envp = []
        for _ in range(envp_len):
            key = make_random_word(random.randrange(0x1, 0x20)).decode()
            value = make_random_word(random.randrange(0x1, 0x20)).decode()
            envp.append(f"{key}={value}".encode())

        ctx = Context(
            architecture=arch, platform=Platforms.Linux.value, bad_bytes=b"\x00"
        )

        emitter = LinuxEmitter.get_emitter(arch, ctx)
        emitter.execve(argv_envp_printer_bin.name.encode(), argv, envp)

        shellcode = assemble(ctx=ctx, assembly=str(emitter))
        qemu_result = run_in_qemu(shellcode=shellcode, arch=arch)

        # XXX
        assert qemu_result.log == "xxx"


@parametrize_qemu_arch
def test_linux_open_net_connection(arch: Architecture[Registers, GpRegisters]):
    # TODO
    pass


def test_linux_emitter_syscall_with_6_arguments():
    # TODO
    pass
