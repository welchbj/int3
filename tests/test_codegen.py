"""Simple tests for the CodeGeneration API.

These tests are not all encompassing. The CodeGeneration implementation is
heavily test by proxy through several other tests files, like program
compilation and the tests related to Choice implementation.

"""

import pytest

from int3 import CodeGenerator, Int3MissingEntityError, Triple


def test_codegen_use_of_invalid_register():
    triple = Triple.from_str("x86_64-linux")
    codegen = CodeGenerator(triple)

    with pytest.raises(Int3MissingEntityError):
        codegen.jump("not_a_reg")


def test_codegen_push_on_mips():
    triple = Triple.from_str("mips-linux")
    codegen = CodeGenerator(triple)

    push_t0_insns = codegen.push("t0").choose().insns
    expected_insns = triple.insns(
        "addi $sp, $sp, -4",
        "sw $t0, 0($sp)",
    )

    assert push_t0_insns == expected_insns


def test_codegen_push_on_arm():
    triple = Triple.from_str("arm-linux")
    codegen = CodeGenerator(triple)

    push_insns = codegen.push("r0", "r1", "r2").choose().insns
    expected_insns = triple.insns("push {r0, r1, r2}")

    assert push_insns == expected_insns


def test_codegen_push_on_aarch64():
    triple = Triple.from_str("aarch64-linux")
    codegen = CodeGenerator(triple)

    push_x0_insns = codegen.push("x0").choose().insns
    expected_insns = triple.insns("str x0, [sp, #-16]!")

    assert push_x0_insns == expected_insns


def test_codegen_pop_on_mips():
    triple = Triple.from_str("mips-linux")
    codegen = CodeGenerator(triple)

    pop_t0_insns = codegen.pop("t0").choose().insns
    expected_insns = triple.insns(
        "lw $t0, 0($sp)",
        "addi $sp, $sp, 4",
    )

    assert pop_t0_insns == expected_insns


def test_codegen_pop_on_arm():
    triple = Triple.from_str("arm-linux")
    codegen = CodeGenerator(triple)

    pop_insns = codegen.pop("r0", "r1", "r2").choose().insns
    expected_insns = triple.insns("pop {r0, r1, r2}")

    assert pop_insns == expected_insns


def test_codegen_pop_on_aarch64():
    triple = Triple.from_str("aarch64-linux")
    codegen = CodeGenerator(triple)

    pop_x0_insns = codegen.pop("x0").choose().insns
    expected_insns = triple.insns("ldr x0, [sp], #16")

    assert pop_x0_insns == expected_insns
