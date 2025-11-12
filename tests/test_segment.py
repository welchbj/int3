import textwrap

import pytest

from int3 import Int3ArgumentError, Segment, Triple


def test_segment_from_asm():
    triple = Triple.from_str("x86_64-linux")
    segment = Segment.from_asm(triple, "mov rax, rbx\nnop")
    assert len(segment.insns) == 2
    assert segment.insns[0].mnemonic == "mov"
    assert segment.insns[1].mnemonic == "nop"
    assert segment.triple == triple
    assert segment.raw == b"\x48\x89\xd8\x90"


def test_segment_with_no_instructions():
    triple = Triple.from_str("x86_64-linux")

    with pytest.raises(Int3ArgumentError):
        Segment(triple, insns=tuple())


def test_segment_str_methods():
    triple = Triple.from_str("x86_64-linux")
    segment = triple.segment(
        "push rax",
        "sub rax, 100",
        "call rax",
        "pop rax",
    )

    assert repr(segment) == textwrap.dedent("""\
        <Segment [
            push rax       (50)
            sub rax, 0x64  (4883e864)
            call rax       (ffd0)
            pop rax        (58)
        ]>""")
