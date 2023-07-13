import pytest

from int3.architectures import Architectures
from int3.errors import Int3ArgumentError


def test_packing():
    x86 = Architectures.x86.value
    x86_64 = Architectures.x86_64.value

    assert x86.pack(0x41, width=0x8) == b"A"
    assert x86.pack(0x41, width=0x10) == b"A\x00"
    assert x86.pack(0x41, width=0x20) == b"A\x00\x00\x00"

    assert x86.pack(0xDEADBEEF) == b"\xef\xbe\xad\xde"
    assert x86_64.pack(0xDEADBEEF) == b"\xef\xbe\xad\xde\x00\x00\x00\x00"

    assert x86.pack(-1, width=0x10) == b"\xff\xff"

    assert x86.pack(-1) == b"\xff\xff\xff\xff"
    assert x86_64.pack(-1) == b"\xff\xff\xff\xff\xff\xff\xff\xff"


def test_unpacking():
    x86 = Architectures.x86.value
    x86_64 = Architectures.x86_64.value

    assert x86.unpack(b"\xff\xff\xff\xff", signed=False) == 0xFFFFFFFF
    assert x86.unpack(b"\xff\xff\xff\xff", signed=True) == -1

    assert x86_64.unpack(b"\xef\xbe\xad\xde", width=0x20, signed=False) == 0xDEADBEEF


def test_invalid_values():
    x86 = Architectures.x86.value

    with pytest.raises(Int3ArgumentError):
        x86.pack(0xFFFFFFFF + 1)

    with pytest.raises(Int3ArgumentError):
        x86.pack(0xFF + 1, width=0x8)

    with pytest.raises(Int3ArgumentError):
        x86.unpack(b"\xff")


def test_invalid_widths():
    x86 = Architectures.x86.value

    for width in (-0x10, -1, 0, 1, 0x11, 0x18, 0x40):
        with pytest.raises(Int3ArgumentError):
            x86.pack(0x41, width=width)
