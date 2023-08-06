from __future__ import annotations

from enum import Enum, auto

from int3.errors import Int3MissingEntityError


class Strategy(Enum):
    GenerationSpeed = auto()
    CodeSize = auto()
    Random = auto()

    @staticmethod
    def from_str(format_style_name: str) -> Strategy:
        format_style = _STRATEGY_MAP.get(format_style_name, None)
        if format_style is None:
            raise Int3MissingEntityError(f"No such strategy {format_style_name}")

        return format_style

    @staticmethod
    def names() -> list[str]:
        return list(_STRATEGY_MAP.keys())


_STRATEGY_MAP = {strategy_enum.name: strategy_enum for strategy_enum in Strategy}
