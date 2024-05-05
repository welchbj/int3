from dataclasses import dataclass
from typing import ClassVar

from .architecture_meta import ArchitectureMeta


@dataclass(frozen=True)
class Architecture:
    meta: ClassVar[ArchitectureMeta]

    # TODO: ABC interface for concrete operations.
