import ast
import binascii
from dataclasses import dataclass

from int3._utils import grouper
from int3.errors import Int3UnsupportedFormatError

from .format_style import FormatStyle


@dataclass
class Formatter:
    """Raw data formatter."""

    style_in: FormatStyle
    style_out: FormatStyle

    width: int = 88

    def format(self, data: bytes) -> bytes:
        """Format data of an input style into an output style.

        .. doctest::

            >>> from int3 import FormatStyle, Formatter
            >>> formatter = Formatter(
            ...     style_in=FormatStyle.Raw, style_out=FormatStyle.Hex
            ... )
            >>> formatter.format(b"AAAA")
            b'41414141'

        """
        parsed_data: bytes

        match self.style_in:
            case FormatStyle.Raw:
                parsed_data = data
            case FormatStyle.Hex:
                data = bytes([i for i in data if bytes([i]) not in b"\n\r\t "])
                parsed_data = binascii.unhexlify(data)
            case FormatStyle.Python:
                parsed_data = ast.literal_eval(f"b'{data.decode()}'")
            case FormatStyle.Assembly:
                raise Int3UnsupportedFormatError(
                    "Assembly format style is not supported in this interface"
                )

        match self.style_out:
            case FormatStyle.Raw:
                return parsed_data
            case FormatStyle.Hex:
                return self._format_as_hex(parsed_data)
            case FormatStyle.Python:
                return self._format_as_python(parsed_data)
            case FormatStyle.Assembly:
                raise Int3UnsupportedFormatError(
                    "Assembly format style is not supported in this interface"
                )

    def _format_as_hex(self, data: bytes) -> bytes:
        chars_per_byte = 2  # Example: ff
        bytes_per_line = self.width // chars_per_byte

        lines = []
        for byte_set in grouper(iter(data), n=bytes_per_line):
            line = "".join(f"{i:02x}" for i in byte_set)
            lines.append(line)

        return "\n".join(lines).encode()

    def _format_as_python(self, data: bytes) -> bytes:
        chars_per_byte = 4  # Example: \x41
        bytes_per_line = (self.width - len('b"') - len('"')) // chars_per_byte

        lines = []
        for byte_set in grouper(iter(data), n=bytes_per_line):
            line = 'b"'
            line += "".join(f"\\x{i:02x}" for i in byte_set)
            line += '"'
            lines.append(line)

        return "\n".join(lines).encode()
