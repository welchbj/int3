from typing import cast

from keystone import Ks, KsError

from int3.context import Context
from int3.errors import Int3WrappedKeystoneError


def assemble(ctx: Context, assembly: str) -> bytes:
    try:
        ks = Ks(
            arch=ctx.architecture.keystone_arch, mode=ctx.architecture.keystone_mode
        )
        encoding, _ = ks.asm(assembly, addr=ctx.vma, as_bytes=True)
    except KsError as e:
        raise Int3WrappedKeystoneError(str(e)) from e

    if encoding is None:
        raise Int3WrappedKeystoneError("No assembly result returned from keystone")

    return cast(bytes, encoding)
