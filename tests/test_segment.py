from int3.codegen import Segment
from int3.platform import Triple


def test_segment_from_asm():
    triple = Triple.from_str("x86_64-linux")
    segment = Segment.from_asm(triple, "mov rax, rbx\nnop")
    assert len(segment.insns) == 2
    assert segment.insns[0].mnemonic == "mov"
    assert segment.insns[1].mnemonic == "nop"
    assert segment.triple == triple
    assert segment.raw == b"\x48\x89\xd8\x90"
