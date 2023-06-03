"""Utilities and constants for dealing with characters."""

from struct import (
    pack)

ALL_CHAR_SET = bytearray(i for i in range(256))


def as_byte(i):
    """Convert an integer to a byte.

    Args:
        i (int): The integer to convert to a byte.

    Returns:
        bytes: The converted value.

    """
    return pack('B', i)


def get_good_chars(bad_chars):
    """Get the good characters from a set of bad characters.

    Args:
        bad_chars (bytes): The bad characters to exclude from the character
            set.

    Returns:
        bytearray: Valid characters with which encoding will be performed.

    """
    good_chars = ALL_CHAR_SET.copy()
    for bc in bad_chars:
        good_chars = good_chars.replace(as_byte(bc), b'')
    return good_chars


def is_valid_gadget(gadget, bad_chars):
    """Determine if a gadget is valid (i.e., contains no bad characters).

    Args:
        gadget (Gadget): A namedtuple-like object with `shellcode` and `asm`
            fields.
        bad_chars (bytearray): The bad characters not allowed to be present.

    Returns:
        bool: Whether the specified gadget is acceptable.

    """
    gadget_chars = bytearray(gadget.shellcode)
    for bc in bad_chars:
        if bc in gadget_chars:
            return False
    return True


def first_valid_gadget(gadgets, bad_chars):
    """Find and return the first valid gagdet in the list.

    Args:
        gadgets (List[Gadget]): The list of gadgets to search.
        bad_chars (bytearray): The bad characters that cannot be present in
            a valid gadget.

    """
    return next((g for g in gadgets if is_valid_gadget(g, bad_chars)), None)
