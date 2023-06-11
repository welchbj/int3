import platform
from dataclasses import dataclass
from enum import Enum

from int3.errors import Int3MissingEntityError

__all__ = ["Platform", "Platforms"]


@dataclass(frozen=True)
class Platform:
    name: str


class Platforms(Enum):
    Windows = Platform(name="Windows")
    Linux = Platform(name="Linux")

    @staticmethod
    def from_host() -> Platform:
        return Platforms.from_str(platform.system())

    @staticmethod
    def from_str(platform_name: str) -> Platform:
        platform = _PLATFORM_MAP.get(platform_name, None)
        if platform is None:
            raise Int3MissingEntityError(f"No such platform {platform_name}")

        return platform

    @staticmethod
    def names() -> list[str]:
        return list(_PLATFORM_MAP.keys())


_PLATFORM_MAP = {
    platform_enum.value.name: platform_enum.value for platform_enum in Platforms
}
