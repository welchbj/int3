from typing import Protocol

from .types import IntVariable, PyBytesArgType


class HighLevelCompilerInterface(Protocol):
    """Protocol definition for the high-level, platform-independent interface."""

    def puts(self, s: PyBytesArgType) -> IntVariable:
        """Write a string to stdout.

        See: https://man7.org/linux/man-pages/man3/puts.3.html

        """
