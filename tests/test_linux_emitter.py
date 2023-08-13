import random
import shutil
import string
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

import pytest

from int3 import Architecture, Architectures, Context, LinuxEmitter, Platforms, assemble


class FilePaths:
    INT3_ROOT_DIR = Path(__file__).resolve().parent.parent
    INT3_BIN_DIR = INT3_ROOT_DIR / "bin"
    INT3_SHELLCODE_RUNNER_SRC = INT3_BIN_DIR / "shellcode_runner.c"


@dataclass(frozen=True)
class QemuResult:
    output: bytes
    log: str


QEMU_ARCHES = [
    # XXX
    # arch.value for arch in Architectures if arch.value.qemu_name != "unsupported"
    arch.value
    for arch in Architectures
    if arch.value.qemu_name != "mips"
]


def compile_src(arch: Architecture, in_file: Path, out_file: Path, static: bool = True):
    cc_bin = f"{arch.toolchain_triple}-gcc"
    if (cc_path := shutil.which(cc_bin)) is None:
        pytest.fail(f"No available gcc binary {cc_bin}")

    args = [str(cc_path), str(in_file), "-o", str(out_file)]
    if static:
        args.append("-static")

    subprocess.check_output(args)


def run_in_qemu(shellcode: bytes, arch: Architecture, strace: bool = True):
    qemu_bin = f"qemu-{arch.qemu_name}"
    if (qemu_path := shutil.which(qemu_bin)) is None:
        pytest.fail(f"No available qemu binary {qemu_bin}")

    with (
        tempfile.NamedTemporaryFile() as runner_bin,
        tempfile.NamedTemporaryFile() as qemu_log_file,
        tempfile.NamedTemporaryFile("wb", buffering=False) as shellcode_file,
    ):
        shellcode_file.write(shellcode)

        compile_src(
            arch=arch,
            in_file=FilePaths.INT3_SHELLCODE_RUNNER_SRC,
            out_file=Path(runner_bin.name),
        )

        args = [str(qemu_path), "-D", qemu_log_file.name]
        if strace:
            args.append("-strace")
        args.extend([runner_bin.name, shellcode_file.name])

        output = subprocess.check_output(args)
        qemu_log_file.seek(0)
        return QemuResult(output, qemu_log_file.read())


@pytest.mark.parametrize("arch", QEMU_ARCHES, ids=lambda x: x.name)
def test_linux_emitter_echo(arch: Architecture):
    ctx = Context(architecture=arch, platform=Platforms.Linux.value)
    emitter = LinuxEmitter.get_emitter_cls_for_arch(arch)(ctx)

    def _make_word(len_: int) -> bytes:
        alphabet = string.ascii_letters.encode()
        return bytes([random.choice(alphabet) for _ in range(len_)])

    short_word = _make_word(arch.byte_size - 1)
    aligned_word = _make_word(arch.byte_size)
    long_word = _make_word(arch.byte_size * 4)

    for word in [short_word, aligned_word, long_word]:
        with emitter.stack_scope(ret=True):
            emitter.echo(word)
        shellcode = assemble(ctx=ctx, assembly=str(emitter))
        assert run_in_qemu(shellcode=shellcode, arch=arch).output == word


def test_linux_emitter_syscall_with_byte_arguments():
    # TODO
    pass


def test_linux_emitter_syscall_with_6_arguments():
    # TODO
    pass
