"""Utilities for user-facing I/O."""

from __future__ import print_function

from colorama import (
    Fore,
    Style)
from functools import partial


def red(s):
    """Add escape sequences to print a string red."""
    return Fore.RED + s + Style.RESET_ALL


def blue(s):
    """Add escape sequences to print a string blue."""
    return Fore.CYAN + s + Style.RESET_ALL


def yellow(s):
    """Add escape sequences to print a string yellow."""
    return Fore.YELLOW + s + Style.RESET_ALL


def format_dword(i):
    """Format an integer to 32-bit hex."""
    return '{0:#010x}'.format(i)


print_i = partial(print, blue('[I] '), sep='')
print_e = partial(print, red('[E] '), sep='')
print_w = partial(print, yellow('[W] '), sep='')
