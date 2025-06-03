from typing import cast

from keystone import Ks, KsError

from int3.architecture import Architecture
from int3.errors import Int3WrappedKeystoneError


def assemble(arch: Architecture, assembly: str, vma: int = 0) -> bytes:
    try:
        ks = Ks(arch=arch.keystone_arch, mode=arch.keystone_mode)
        encoding, _ = ks.asm(assembly, addr=vma, as_bytes=True)
    except KsError as e:
        raise Int3WrappedKeystoneError(str(e)) from e

    if encoding is None:
        raise Int3WrappedKeystoneError("No assembly result returned from keystone")

    return cast(bytes, encoding)
