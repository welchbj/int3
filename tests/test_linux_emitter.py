import os
import random
import stat
import string
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

from .qemu import parametrize_qemu_arch, run_in_qemu


@parametrize_qemu_arch
def test_linux_emitter_write_to_file(
    arch: Architecture[Registers, GpRegisters], tmp_path: Path
):
    # We add "/" as a bad byte since we know this will be tmp_path generated
    # paths.
    ctx = Context(architecture=arch, platform=Platforms.Linux.value, bad_bytes=b"\x00/")

    def _make_word(len_: int) -> bytes:
        alphabet = string.ascii_letters.encode()
        return bytes([random.choice(alphabet) for _ in range(len_)])

    short_word = _make_word(arch.byte_size - 1)
    aligned_word = _make_word(arch.byte_size)
    long_word = _make_word(arch.byte_size * 4)

    for word in [short_word, aligned_word, long_word]:
        emitter = LinuxEmitter.get_emitter_cls_for_arch(arch)(ctx)

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


def test_linux_emitter_syscall_with_byte_arguments():
    # TODO
    pass


def test_linux_emitter_syscall_with_6_arguments():
    # TODO
    pass
