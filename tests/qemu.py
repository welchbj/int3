import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

import pytest

from int3 import Architecture, Architectures, Compiler


class FilePaths:
    INT3_ROOT_DIR = Path(__file__).resolve().parent.parent
    INT3_BIN_DIR = INT3_ROOT_DIR / "bin"
    INT3_SHELLCODE_RUNNER_SRC = INT3_BIN_DIR / "shellcode_runner.c"
    INT3_ARGV_ENVP_PRINTER_SRC = INT3_BIN_DIR / "argv_envp_printer.c"


@dataclass(frozen=True)
class QemuResult:
    stdout: bytes
    stderr: bytes
    log: str


QEMU_ARCHES = [
    arch.value
    for arch in Architectures
    # XXX
    # if arch.value.qemu_name != "unsupported"
    if arch.name == "x86_64"
]


def _name_getter(obj):
    return getattr(obj, "name", None)


parametrize_qemu_arch = pytest.mark.parametrize("arch", QEMU_ARCHES, ids=_name_getter)


def compile_src(
    arch: Architecture,
    in_file: Path,
    out_file: Path,
    static: bool = True,
    debug: bool = True,
):
    cc_bin = f"{arch.toolchain_triple}-gcc"
    if (cc_path := shutil.which(cc_bin)) is None:
        pytest.fail(f"No available gcc binary {cc_bin}")

    args = [str(cc_path), str(in_file), "-o", str(out_file)]
    if static:
        args.append("-static")
    if debug:
        args.append("-g")

    subprocess.check_output(args)


def run_in_qemu(compiler: Compiler, load_addr: int | None = None, strace: bool = True):
    arch = compiler.arch
    asm = compiler.compile()

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
        shellcode_file.write(asm)

        compile_src(
            arch=arch,
            in_file=FilePaths.INT3_SHELLCODE_RUNNER_SRC,
            out_file=Path(runner_bin.name),
        )

        args = [str(qemu_path), "-D", qemu_log_file.name]
        if strace:
            args.append("-strace")
        args.extend([runner_bin.name, shellcode_file.name])
        if load_addr is not None:
            args.append(hex(load_addr))

        print("Debug this with:")
        if load_addr is None:
            print(f"{qemu_path} -g 12345 {runner_bin.name} {shellcode_file.name}")
        else:
            print(f"{qemu_path} -g 12345 {runner_bin.name} {shellcode_file.name} {load_addr:#x}")
        print(
            f'gdb-multiarch -ex "file {runner_bin.name}" '
            '-ex "gef-remote --qemu-user 127.0.0.1 12345" -ex "continue"'
        )

        result = subprocess.run(args, capture_output=True)
        qemu_log_file.seek(0)
        return QemuResult(
            stdout=result.stdout,
            stderr=result.stderr,
            log=qemu_log_file.read(),
        )
