import random
import string

from int3 import Architecture, Context, LinuxEmitter, Platforms, assemble

from .qemu import parametrize_qemu_arch, run_in_qemu


@parametrize_qemu_arch
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
