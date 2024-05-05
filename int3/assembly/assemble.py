from typing import cast

from keystone import Ks, KsError

from int3.architectures import ArchitectureMeta
from int3.errors import Int3WrappedKeystoneError


def assemble(arch_meta: ArchitectureMeta, assembly: str, vma: int = 0) -> bytes:
    try:
        ks = Ks(arch=arch_meta.keystone_arch, mode=arch_meta.keystone_mode)
        encoding, _ = ks.asm(assembly, addr=vma, as_bytes=True)
    except KsError as e:
        raise Int3WrappedKeystoneError(str(e)) from e

    if encoding is None:
        raise Int3WrappedKeystoneError("No assembly result returned from keystone")

    return cast(bytes, encoding)
