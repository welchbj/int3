from __future__ import annotations

import platform
from enum import Enum, auto

from int3.errors import Int3ArgumentError


class Platform(Enum):
    Linux = auto()
    Windows = auto()

    @staticmethod
    def from_host() -> Platform:
        return Platform.from_str(platform.system().lower())

    @staticmethod
    def from_str(platform_str: str) -> Platform:
        match platform_str.lower():
            case "linux":
                return Platform.Linux
            case "windows":
                return Platform.Windows
            case _:
                raise Int3ArgumentError(f"Unknown platform string {platform_str}")
