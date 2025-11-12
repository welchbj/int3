import pytest

from int3 import CodeGenerator, Int3NoValidChoiceError, Segment, Triple, Choice, FluidSegment


def test_choice_with_single_option():
    triple = Triple.from_str("x86_64-linux")
    codegen = CodeGenerator(triple)

    insn = triple.one_insn_or_raise("pop rax")
    selection = codegen.choice(insn).choose()
    assert len(selection.insns) == 1
    assert selection.insns[0] == insn


def test_choice_with_no_options():
    with pytest.raises(Int3NoValidChoiceError):
        Choice(tuple())


def test_fluid_segment_with_no_steps():
    with pytest.raises(Int3NoValidChoiceError):
        FluidSegment(tuple())


def test_choice_with_no_valid_options():
    triple = Triple.from_str("x86_64-linux")
    codegen = CodeGenerator(triple)

    insns = triple.insns(
        "jmp rax",
        "jmp rbx",
    )
    for insn in insns:
        # Ensure our expected bad byte is in the instructions. We'll make
        # this a bad byte, invalidating all of the options.
        assert b"\xff" in insn.raw

    choice = codegen.choice(*insns)
    with pytest.raises(Int3NoValidChoiceError):
        choice.choose(bad_bytes=b"\xff")


def test_choice_with_fluid_segments():
    triple = Triple.from_str("x86_64-linux")
    codegen = CodeGenerator(triple)

    fluid_segment = codegen.segment(
        codegen.xor("rax", "rax"),
        codegen.mov("rbx", 0xBEEF),
        codegen.segment(
            codegen.choice(
                codegen.add("rax", 0xDEAD),
                codegen.sub("rax", "rbx"),
            )
        ),
        codegen.jump("rbx"),
    )

    # Validate that the expected program is created, overcoming a bad byte constraint
    # in one of the choice paths.
    expected_insns = triple.insns(
        "xor rax, rax",
        "mov rbx, 0xBEEF",
        "add rax, 0xDEAD",
        "sub rax, rbx",
        "jmp rbx",
    )
    expected_segment = Segment.from_insns(triple, *expected_insns)
    assert fluid_segment.choose(bad_bytes=b"\xde\xad") == expected_segment

    # Validate that segment choosing fails when we introduce bad byte constraints.
    with pytest.raises(Int3NoValidChoiceError):
        fluid_segment.choose(bad_bytes=b"\xbe")


def test_fluid_segment_with_options_of_different_triples():
    x86_64_triple = Triple.from_str("x86_64-linux")
    mips_triple = Triple.from_str("mips-linux")

    # TODO

    assert False


def test_build_choice_with_repeat():
    # TODO
    assert False
