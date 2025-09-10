from __future__ import annotations

from enum import Enum, auto

from int3.errors import Int3MissingEntityError


class FormatStyle(Enum):
    """Style to use for formatting text."""

    Raw = auto()
    Hex = auto()
    Python = auto()
    Assembly = auto()

    @staticmethod
    def from_str(format_style_name: str) -> FormatStyle:
        """Factory method to create an instance from a string name."""
        format_style = _FORMAT_STYLE_MAP.get(format_style_name, None)
        if format_style is None:
            raise Int3MissingEntityError(f"No such format style {format_style_name}")

        return format_style

    @staticmethod
    def names() -> list[str]:
        """Get all supported format style names."""
        return list(_FORMAT_STYLE_MAP.keys())


_FORMAT_STYLE_MAP = {
    format_style_enum.name: format_style_enum for format_style_enum in FormatStyle
}
