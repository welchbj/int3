from __future__ import annotations

from enum import Enum, auto

from int3.errors import Int3MissingEntityError


class FormatStyle(Enum):
    Raw = auto()
    Hex = auto()
    Python = auto()
    Assembly = auto()

    @staticmethod
    def from_str(format_style_name: str) -> FormatStyle:
        format_style = _FORMAT_STYLE_MAP.get(format_style_name, None)
        if format_style is None:
            raise Int3MissingEntityError(f"No such format style {format_style_name}")

        return format_style

    @staticmethod
    def names() -> list[str]:
        return list(_FORMAT_STYLE_MAP.keys())


_FORMAT_STYLE_MAP = {
    format_style_enum.name: format_style_enum for format_style_enum in FormatStyle
}
