from __future__ import annotations

import platform
from enum import Enum, auto

from int3.errors import Int3ArgumentError


class Platform(Enum):
    """Supported platform types."""

    Linux = auto()
    Windows = auto()

    @staticmethod
    def from_host() -> Platform:
        """Derive the host's platform."""
        return Platform.from_str(platform.system().lower())

    @staticmethod
    def from_str(platform_str: str) -> Platform:
        """Derive a platform from its string name.

        .. doctest::

            >>> from int3 import Platform
            >>> Platform.from_str("linux").name
            'Linux'

        """
        match platform_str.lower():
            case "linux":
                return Platform.Linux
            case "windows":
                return Platform.Windows
            case _:
                raise Int3ArgumentError(f"Unknown platform string {platform_str}")
