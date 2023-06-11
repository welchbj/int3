from dataclasses import dataclass

from int3.architectures import Architecture
from int3.platforms import Platform

__all__ = ["Context"]


@dataclass(frozen=True)
class Context:
    architecture: Architecture
    platform: Platform

    bad_bytes: bytes = b""
    vma: int = 0
    usable_stack: bool = True
