from keystone import Ks

from int3.context import Context


def assemble(ctx: Context, assembly: str) -> bytes:
    ks = Ks(arch=ctx.architecture.keystone_arch, mode=ctx.architecture.keystone_mode)

    # TODO: Standardize error abstraction layer.

    encoding, _ = ks.asm(assembly, addr=ctx.vma, as_bytes=True)
    return encoding
