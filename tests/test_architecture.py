import pytest

from int3.architecture import Architectures
from int3.errors import Int3ArgumentError, Int3InsufficientWidthError


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


def test_invalid_pack_unpack_values():
    x86 = Architectures.x86.value

    with pytest.raises(Int3ArgumentError):
        x86.pack(0xFFFFFFFF + 1)

    with pytest.raises(Int3ArgumentError):
        x86.pack(0xFF + 1, width=0x8)

    with pytest.raises(Int3ArgumentError):
        x86.unpack(b"\xff")


def test_invalid_pack_widths():
    x86 = Architectures.x86.value

    for width in (-0x10, -1, 0, 1, 0x11, 0x18, 0x40):
        with pytest.raises(Int3ArgumentError):
            x86.pack(0x41, width=width)


def test_pad():
    x86 = Architectures.x86.value
    x86_64 = Architectures.x86_64.value

    assert x86.pad(b"", width=0x8) == b"\x00"
    assert x86.pad(b"", width=0x10, fill_byte=b"B") == b"BB"
    assert x86.pad(b"AAAA") == b"AAAA"

    assert x86.pad(b"A") == b"A\x00\x00\x00"
    assert x86_64.pad(b"A") == b"A\x00\x00\x00\x00\x00\x00\x00"


def test_invalid_pad_widths():
    x86 = Architectures.x86.value

    with pytest.raises(Int3InsufficientWidthError):
        x86.pad(b"X" * 5)


def test_align_to_min_insn_width():
    x86 = Architectures.x86.value
    mips = Architectures.Mips.value
    x86_64 = Architectures.x86_64.value

    for arch in [x86, mips, x86_64]:
        assert arch.align_down_to_min_insn_width(0) == 0
        assert arch.align_up_to_min_insn_width(0) == 0

    assert x86.align_down_to_min_insn_width(1) == 1

    assert mips.align_down_to_min_insn_width(1) == 0
    assert mips.align_down_to_min_insn_width(5) == 4
    assert mips.align_up_to_min_insn_width(5) == 8
    assert mips.align_down_to_min_insn_width(16) == 16
    assert mips.align_up_to_min_insn_width(16) == 16
