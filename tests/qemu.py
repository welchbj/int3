import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

import pytest

from int3.architectures import Architecture, Architectures


class FilePaths:
    INT3_ROOT_DIR = Path(__file__).resolve().parent.parent
    INT3_BIN_DIR = INT3_ROOT_DIR / "bin"
    INT3_SHELLCODE_RUNNER_SRC = INT3_BIN_DIR / "shellcode_runner.c"


@dataclass(frozen=True)
class QemuResult:
    log: str


QEMU_ARCHES = [
    # XXX
    # arch.value for arch in Architectures if arch.value.qemu_name != "unsupported"
    arch.value
    for arch in Architectures
    if arch.value.qemu_name != "mips"
]


def _name_getter(obj):
    return getattr(obj, "name", None)


parametrize_qemu_arch = pytest.mark.parametrize("arch", QEMU_ARCHES, ids=_name_getter)


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
        tempfile.NamedTemporaryFile(delete=False) as runner_bin,
        tempfile.NamedTemporaryFile("r", delete=False) as qemu_log_file,
        tempfile.NamedTemporaryFile(
            "wb", delete=False, buffering=False
        ) as shellcode_file,
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

        print("Debug this with:")
        print(f"{qemu_path} -g 12345 {runner_bin.name} {shellcode_file.name}")
        print(
            f'gdb-multiarch -ex "file {runner_bin.name}" '
            '-ex "gef-remote --qemu-user 127.0.0.1 12345" -ex "continue"'
        )

        subprocess.run(args, capture_output=True)
        qemu_log_file.seek(0)
        return QemuResult(qemu_log_file.read())
