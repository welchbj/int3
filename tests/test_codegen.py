"""Simple tests for the CodeGeneration API.

These tests are not all encompassing. The CodeGeneration implementation is
heavily test by proxy through several other tests files, like program
compilation and the tests related to Choice implementation.

"""

import pytest

from int3 import CodeGenerator, Int3CodeGenerationError, Int3MissingEntityError, Triple


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


def test_codegen_add_two_operands():
    triple = Triple.from_str("x86_64-linux")
    codegen = CodeGenerator(triple)
    insns = codegen.add("rax", "rbx").choose().insns
    expected = triple.insns("add rax, rbx")
    assert insns == expected

    triple = Triple.from_str("aarch64-linux")
    codegen = CodeGenerator(triple)
    insns = codegen.add("x0", "x1").choose().insns
    expected = triple.insns("add x0, x0, x1")
    assert insns == expected

    triple = Triple.from_str("mips-linux")
    codegen = CodeGenerator(triple)
    insns = codegen.add("t0", "t1").choose().insns
    expected = triple.insns("add $t0, $t1")
    assert insns == expected


def test_codegen_add_three_operands():
    triple = Triple.from_str("aarch64-linux")
    codegen = CodeGenerator(triple)
    insns = codegen.add("x0", "x1", "x2").choose().insns
    expected = triple.insns("add x0, x1, x2")
    assert insns == expected

    triple = Triple.from_str("mips-linux")
    codegen = CodeGenerator(triple)
    insns = codegen.add("t0", "t1", "t2").choose().insns
    expected = triple.insns("addu $t0, $t1, $t2")
    assert insns == expected

    # x86 uses LEA for three-operand add.
    triple = Triple.from_str("x86_64-linux")
    codegen = CodeGenerator(triple)
    insns = codegen.add("rax", "rbx", "rcx").choose().insns
    expected = triple.insns("lea rax, [rbx + rcx]")
    assert insns == expected


def test_codegen_sub_two_operands():
    triple = Triple.from_str("x86_64-linux")
    codegen = CodeGenerator(triple)
    insns = codegen.sub("rax", "rbx").choose().insns
    expected = triple.insns("sub rax, rbx")
    assert insns == expected

    triple = Triple.from_str("aarch64-linux")
    codegen = CodeGenerator(triple)
    insns = codegen.sub("x0", "x1").choose().insns
    expected = triple.insns("sub x0, x0, x1")
    assert insns == expected

    triple = Triple.from_str("mips-linux")
    codegen = CodeGenerator(triple)
    insns = codegen.sub("t0", "t1").choose().insns
    expected = triple.insns("sub $t0, $t1")
    assert insns == expected


def test_codegen_sub_three_operands():
    triple = Triple.from_str("aarch64-linux")
    codegen = CodeGenerator(triple)
    insns = codegen.sub("x0", "x1", "x2").choose().insns
    expected = triple.insns("sub x0, x1, x2")
    assert insns == expected

    triple = Triple.from_str("mips-linux")
    codegen = CodeGenerator(triple)
    insns = codegen.sub("t0", "t1", "t2").choose().insns
    expected = triple.insns("subu $t0, $t1, $t2")
    assert insns == expected

    # x86 does not support three-operand sub.
    triple = Triple.from_str("x86_64-linux")
    codegen = CodeGenerator(triple)
    with pytest.raises(Int3CodeGenerationError):
        codegen.sub("rax", "rbx", "rcx")
