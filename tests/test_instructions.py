import pytest

from int3 import (
    Architectures,
    Int3ArgumentError,
    Int3CodeGenerationError,
    MemoryOperand,
    Platform,
    Triple,
)

# =============================================================================
# Instruction Factory and Parsing
# =============================================================================


def test_triple_insn_factory():
    x86_64 = Architectures.x86_64.value
    Mips = Architectures.Mips.value

    linux_x86_64 = Triple(x86_64, Platform.Linux)
    linux_mips = Triple(Mips, Platform.Linux)

    # x86_64 tests
    # ~~~~~~~~~~~~
    insns = linux_x86_64.insns(
        "pop rdx",
        "syscall",
        "add rax, r15",
        "lea rdi, [rip+0x100]",
        "mov byte ptr [rax], 0x1",
        "call qword ptr [rsp-0x10]",
    )
    assert len(insns) == 6

    # pop rdx
    assert insns[0].mnemonic == "pop"
    assert insns[0].is_pop()
    assert insns[0].op_str == "rdx"
    assert len(insns[0].operands) == 1
    assert insns[0].operands.is_reg(0)
    assert not insns[0].operands.is_imm(0)
    assert insns[0].operands.reg(0) == x86_64.reg("rdx")
    assert insns[0].operands.token(0) == "rdx"

    # syscall
    assert insns[1].mnemonic == "syscall"
    assert insns[1].is_syscall()
    assert insns[1].op_str == ""
    assert len(insns[1].operands) == 0

    # add rax, r15
    assert insns[2].mnemonic == "add"
    assert insns[2].is_add()
    assert insns[2].op_str == "rax, r15"
    assert len(insns[2].operands) == 2
    assert insns[2].operands.is_reg(0)
    assert insns[2].operands.is_reg(1)
    assert insns[2].operands.reg(0) == x86_64.reg("rax")
    assert insns[2].operands.reg(1) == x86_64.reg("r15")
    assert insns[2].operands.token(0) == "rax"
    assert insns[2].operands.token(1) == "r15"

    # lea rdi, [rip+0x100]
    assert insns[3].mnemonic == "lea"
    assert insns[3].is_mov()
    assert insns[3].op_str == "rdi, [rip + 0x100]"
    assert len(insns[3].operands) == 2
    assert insns[3].operands.is_reg(0)
    assert insns[3].operands.reg(0) == x86_64.reg("rdi")
    assert insns[3].operands.is_mem(1)
    assert insns[3].operands.mem(1) == MemoryOperand(x86_64.reg("rip"), 0x100)
    assert insns[3].operands.token(0) == "rdi"
    assert insns[3].operands.token(1) == "[rip + 0x100]"

    # mov byte ptr [rax], 0x1
    assert insns[4].mnemonic == "mov"
    assert insns[4].is_mov()
    assert len(insns[4].operands) == 2
    assert insns[4].operands.mem(0) == MemoryOperand(x86_64.reg("rax"), 0, "byte ptr")
    assert insns[4].operands.imm(1) == 1
    assert insns[4].operands.token(0) == "byte ptr [rax]"
    assert insns[4].operands.token(1) == "1"

    # call qword ptr [rsp-0x10]
    assert insns[5].mnemonic == "call"
    assert insns[5].is_call()
    assert len(insns[5].operands) == 1
    assert insns[5].operands.is_mem(0)
    assert insns[5].operands.mem(0) == MemoryOperand(
        x86_64.reg("rsp"), -0x10, "qword ptr"
    )
    assert insns[5].operands.token(0) == "qword ptr [rsp - 0x10]"

    # Mips tests
    # ~~~~~~~~~~
    insns = linux_mips.insns(
        "lui $v0, 0xcafe",
        "ori $v0, $v0, 0xbeef",
        "add $a0, $zero, $v1",
        "syscall",
    )
    assert len(insns) == 4

    # lui $v0, 0xcafe
    assert insns[0].mnemonic == "lui"
    assert insns[0].is_mov()
    assert len(insns[0].operands) == 2
    assert insns[0].operands.reg(0) == Mips.reg("v0")
    assert insns[0].operands.imm(1) == 0xCAFE

    # ori $v0, $v0, 0xbeef
    assert insns[1].mnemonic == "ori"
    assert insns[1].is_or()
    assert len(insns[1].operands) == 3
    assert insns[1].operands.reg(0) == Mips.reg("v0")
    assert insns[1].operands.reg(1) == Mips.reg("v0")
    assert insns[1].operands.imm(2) == 0xBEEF

    # add $a0, $zero, $v1
    assert insns[2].mnemonic == "add"
    assert insns[2].is_add()
    assert len(insns[2].operands) == 3
    assert insns[2].operands.reg(0) == Mips.reg("a0")
    assert insns[2].operands.reg(1) == Mips.reg("zero")
    assert insns[2].operands.reg(2) == Mips.reg("v1")

    # syscall
    assert insns[3].mnemonic == "syscall"
    assert insns[3].is_syscall()
    assert insns[3].op_str == ""
    assert len(insns[3].operands) == 0


def test_instruction_equivalence():
    """Test equivalent generated instructions are Pythonically equal, too."""
    linux_x86_64 = Triple.from_str("x86_64-linux")
    push_rax_one = linux_x86_64.one_insn_or_raise("push rax")
    push_rax_two = linux_x86_64.one_insn_or_raise("push rax")
    assert push_rax_one == push_rax_two


# =============================================================================
# Operand Access
# =============================================================================


def test_access_operand_out_of_bounds():
    linux_x86_64 = Triple.from_str("x86_64-linux")

    insn = linux_x86_64.one_insn_or_raise("mov eax, 123")
    with pytest.raises(Int3CodeGenerationError):
        insn.operands.replace(2, 0xBEEF)

    insn = linux_x86_64.one_insn_or_raise("syscall")
    with pytest.raises(Int3CodeGenerationError):
        insn.operands.reg(0)
    with pytest.raises(Int3CodeGenerationError):
        insn.operands.imm(-1)


def test_access_operand_via_negative_index():
    x86_64 = Architectures.x86_64.value
    linux_x86_64 = Triple(x86_64, Platform.Linux)
    linux_x86_64 = Triple.from_str("x86_64-linux")

    insn = linux_x86_64.one_insn_or_raise("xor rax, rbx")
    assert insn.operands.reg(-1) == x86_64.reg("rbx")
    assert insn.operands.reg(-2) == x86_64.reg("rax")

    with pytest.raises(Int3CodeGenerationError):
        insn.operands.token(-3)


def test_only_register_operand_detection():
    Aarch64 = Architectures.Aarch64.value
    aarch64_triple = Triple(Aarch64, Platform.Linux)

    for case in ["sub x0, x1, x2", "br x9"]:
        insn = aarch64_triple.one_insn_or_raise(case)
        assert insn.has_only_register_operands()

    for case in ["ret", "mov x0, #0"]:
        insn = aarch64_triple.one_insn_or_raise(case)
        assert not insn.has_only_register_operands()


# =============================================================================
# Operand Modification
# =============================================================================


def test_patch_immediates_and_registers():
    x86_64 = Architectures.x86_64.value
    Mips = Architectures.Mips.value

    linux_x86_64 = Triple(x86_64, Platform.Linux)
    linux_mips = Triple(Mips, Platform.Linux)

    insn = linux_x86_64.one_insn_or_raise("add rax, rcx")
    insn = insn.operands.replace(-1, 0xBEEF)
    assert str(insn).startswith("add rax, 0xbeef")

    insn = linux_mips.one_insn_or_raise("xor $a0, $v0, $zero")
    insn = insn.operands.replace(1, "t9")
    assert str(insn).startswith("xor $a0, $t9, $zero")


def test_patch_memory_operand():
    x86_64 = Architectures.x86_64.value
    linux_x86_64 = Triple(x86_64, Platform.Linux)

    insn = linux_x86_64.one_insn_or_raise("mov dword ptr [ebx], 0xbeef")
    insn = insn.operands.replace(0, MemoryOperand(x86_64.reg("rax"), 0x64, "qword ptr"))
    insn = insn.operands.replace(-1, 0xDEAD)
    assert str(insn).startswith("mov qword ptr [rax + 0x64], 0xdead")


# =============================================================================
# Memory Operands
# =============================================================================


def test_memory_operand_str():
    x86_64 = Architectures.x86_64.value
    rax = x86_64.reg("rax")

    assert str(MemoryOperand(rax, 100)) == "[rax + 100]"
    assert str(MemoryOperand(rax, 0)) == "[rax]"
    assert str(MemoryOperand(rax, -200)) == "[rax - 200]"
    assert str(MemoryOperand(rax, 1, "byte ptr")) == "byte ptr [rax + 1]"


def test_mips_memory_operand():
    Mips = Architectures.Mips.value
    linux_mips = Triple(Mips, Platform.Linux)

    # Load instruction with MIPS-style offset(base) syntax.
    insn = linux_mips.one_insn_or_raise("lw $t0, 0x10($sp)")
    assert insn.is_load()
    assert not insn.is_store()
    assert insn.has_memory_operand()
    assert insn.operands.is_mem(1)
    mem = insn.memory_operand()
    assert mem.reg == Mips.reg("sp")
    assert mem.offset == 0x10
    assert mem.ptr_desc == ""

    # Store instruction with zero offset.
    insn = linux_mips.one_insn_or_raise("sw $ra, 0($sp)")
    assert insn.is_store()
    assert not insn.is_load()
    assert insn.has_memory_operand()
    mem = insn.memory_operand()
    assert mem.reg == Mips.reg("sp")
    assert mem.offset == 0

    # Store with larger offset.
    insn = linux_mips.one_insn_or_raise("sw $a0, 0x100($t9)")
    mem = insn.memory_operand()
    assert mem.reg == Mips.reg("t9")
    assert mem.offset == 0x100


def test_arm_memory_operand():
    Arm = Architectures.Arm.value
    linux_arm = Triple(Arm, Platform.Linux)

    # Load instruction with ARM-style [base, #offset] syntax.
    insn = linux_arm.one_insn_or_raise("ldr r0, [sp, #0x10]")
    assert insn.is_load()
    assert not insn.is_store()
    assert insn.has_memory_operand()
    assert insn.operands.is_mem(1)
    mem = insn.memory_operand()
    assert mem.reg == Arm.reg("sp")
    assert mem.offset == 0x10
    assert mem.ptr_desc == ""

    # Store instruction with zero offset.
    insn = linux_arm.one_insn_or_raise("str lr, [sp]")
    assert insn.is_store()
    assert not insn.is_load()
    assert insn.has_memory_operand()
    mem = insn.memory_operand()
    assert mem.reg == Arm.reg("sp")
    assert mem.offset == 0

    # Store with negative offset.
    insn = linux_arm.one_insn_or_raise("str r0, [r1, #-4]")
    mem = insn.memory_operand()
    assert mem.reg == Arm.reg("r1")
    assert mem.offset == -4


def test_aarch64_memory_operand():
    Aarch64 = Architectures.Aarch64.value
    linux_aarch64 = Triple(Aarch64, Platform.Linux)

    # Load instruction with AArch64-style [base, #offset] syntax.
    insn = linux_aarch64.one_insn_or_raise("ldr x0, [sp, #0x10]")
    assert insn.is_load()
    assert not insn.is_store()
    assert insn.has_memory_operand()
    assert insn.operands.is_mem(1)
    mem = insn.memory_operand()
    assert mem.reg == Aarch64.reg("sp")
    assert mem.offset == 0x10
    assert mem.ptr_desc == ""

    # Store instruction with zero offset.
    insn = linux_aarch64.one_insn_or_raise("str x30, [sp]")
    assert insn.is_store()
    assert not insn.is_load()
    assert insn.has_memory_operand()
    mem = insn.memory_operand()
    assert mem.reg == Aarch64.reg("sp")
    assert mem.offset == 0

    # Store with larger offset.
    insn = linux_aarch64.one_insn_or_raise("str x0, [x1, #0x100]")
    mem = insn.memory_operand()
    assert mem.reg == Aarch64.reg("x1")
    assert mem.offset == 0x100


# =============================================================================
# Register Read/Write Tracking
# =============================================================================


def test_regs_read_and_write():
    """Test regs_read and regs_write properties."""
    x86_64 = Architectures.x86_64.value
    Aarch64 = Architectures.Aarch64.value

    linux_x86_64 = Triple(x86_64, Platform.Linux)
    linux_aarch64 = Triple(Aarch64, Platform.Linux)

    insn = linux_x86_64.one_insn_or_raise("add rax, rbx")
    assert x86_64.reg("rax") in insn.regs_read
    assert x86_64.reg("rbx") in insn.regs_read
    assert x86_64.reg("rax") in insn.regs_written

    insn = linux_x86_64.one_insn_or_raise("mov rax, rbx")
    assert x86_64.reg("rbx") in insn.regs_read
    assert x86_64.reg("rax") in insn.regs_written
    assert x86_64.reg("rax") not in insn.regs_read

    insn = linux_aarch64.one_insn_or_raise("blr x8")
    assert Aarch64.reg("x8") in insn.regs_read
    assert Aarch64.reg("lr") in insn.regs_written
    assert Aarch64.reg("x8") not in insn.regs_written

    insn = linux_aarch64.one_insn_or_raise("br x9")
    assert Aarch64.reg("x9") in insn.regs_read
    assert len(insn.regs_written) == 0

    insn = linux_aarch64.one_insn_or_raise("add x0, x1, x2")
    assert Aarch64.reg("x1") in insn.regs_read
    assert Aarch64.reg("x2") in insn.regs_read
    assert Aarch64.reg("x0") in insn.regs_written
    assert Aarch64.reg("x0") not in insn.regs_read


# =============================================================================
# ARM Register Lists
# =============================================================================


def test_arm_register_list_operand_access_as_individual_registers():
    Arm = Architectures.Arm.value
    linux_arm = Triple(Arm, Platform.Linux)

    # Push/Pop: all operands come from the register list.
    insn = linux_arm.one_insn_or_raise("push {r0, r1, r2}")
    assert len(insn.operands) == 3
    assert all(insn.operands.is_reg(i) for i in range(3))
    assert insn.operands.reg(0) == Arm.reg("r0")
    assert insn.operands.reg(-1) == Arm.reg("r2")

    insn = linux_arm.one_insn_or_raise("pop {r4, r8}")
    assert len(insn.operands) == 2
    assert insn.operands.reg(0) == Arm.reg("r4")
    assert insn.operands.reg(1) == Arm.reg("r8")

    # LDM: base register (index 0) followed by register list (indices 1+).
    insn = linux_arm.one_insn_or_raise("ldm r0, {r1, r2, r3}")
    assert len(insn.operands) == 4
    assert insn.operands.reg(0) == Arm.reg("r0")
    assert insn.operands.reg(1) == Arm.reg("r1")
    assert insn.operands.reg(3) == Arm.reg("r3")

    # Single-register lists.
    insn = linux_arm.one_insn_or_raise("pop {r4}")
    assert len(insn.operands) == 1
    assert insn.operands.reg(0) == Arm.reg("r4")


def test_arm_register_list_operand_access_as_register_list():
    Arm = Architectures.Arm.value
    linux_arm = Triple(Arm, Platform.Linux)

    insn = linux_arm.one_insn_or_raise("push {r0, r1, r2}")
    reg_list = insn.operands.reg_list(0)

    # Collection protocol.
    assert len(reg_list) == 3
    assert Arm.reg("r1") in reg_list
    assert Arm.reg("r8") not in reg_list
    assert list(reg_list) == [Arm.reg("r0"), Arm.reg("r1"), Arm.reg("r2")]

    # Underlying tuple access.
    assert reg_list.regs == (Arm.reg("r0"), Arm.reg("r1"), Arm.reg("r2"))

    # String representation sorts registers.
    assert str(reg_list) == "{r0, r1, r2}"

    # Immutable replacement returns a new instance.
    new_list = reg_list.with_replaced(1, Arm.reg("r5"))
    assert new_list.regs == (Arm.reg("r0"), Arm.reg("r5"), Arm.reg("r2"))
    assert reg_list.regs == (Arm.reg("r0"), Arm.reg("r1"), Arm.reg("r2"))


def test_arm_register_list_identification():
    Arm = Architectures.Arm.value
    linux_arm = Triple(Arm, Platform.Linux)

    # Push: all operands are in the register list.
    insn = linux_arm.one_insn_or_raise("push {r0, r1}")
    assert insn.operands.is_reg_list(0)
    assert insn.operands.is_reg_list(1)

    # reg_list() returns the RegisterListOperand with its own API.
    reg_list = insn.operands.reg_list(0)
    assert len(reg_list) == 2
    assert Arm.reg("r0") in reg_list
    assert Arm.reg("r8") not in reg_list

    # LDM: base register is NOT in list, rest are.
    insn = linux_arm.one_insn_or_raise("ldm r0, {r1, r2}")
    assert not insn.operands.is_reg_list(0)
    assert insn.operands.is_reg_list(1)
    assert insn.operands.is_reg_list(2)

    # Regular instructions have no register lists.
    insn = linux_arm.one_insn_or_raise("mov r0, r1")
    assert not insn.operands.is_reg_list(0)
    assert not insn.operands.is_reg_list(1)

    with pytest.raises(Int3ArgumentError):
        insn.operands.reg_list(0)


def test_arm_register_list_replacement():
    Arm = Architectures.Arm.value
    linux_arm = Triple(Arm, Platform.Linux)

    # Replace r1 with r5 in {r0, r1, r2} -> re-sorts to {r0, r2, r5}.
    insn = linux_arm.one_insn_or_raise("push {r0, r1, r2}")
    new_insn = insn.operands.replace(1, "r5")
    assert new_insn.operands.reg(0) == Arm.reg("r0")
    assert new_insn.operands.reg(1) == Arm.reg("r2")
    assert new_insn.operands.reg(2) == Arm.reg("r5")

    # Natural ordering: r2 < r10 (numeric, not lexicographic).
    new_insn = insn.operands.replace(1, "r10")
    assert new_insn.operands.reg(1) == Arm.reg("r2")
    assert new_insn.operands.reg(2) == Arm.reg("sl")  # Capstone alias for r10

    # Pop replacement.
    insn = linux_arm.one_insn_or_raise("pop {r4, r8}")
    new_insn = insn.operands.replace(1, "r5")
    assert new_insn.operands.reg(0) == Arm.reg("r4")
    assert new_insn.operands.reg(1) == Arm.reg("r5")

    # LDM: replace base register (index 0, not in list).
    insn = linux_arm.one_insn_or_raise("ldm r0, {r1, r2}")
    new_insn = insn.operands.replace(0, "r3")
    assert new_insn.operands.reg(0) == Arm.reg("r3")
    assert new_insn.operands.reg(1) == Arm.reg("r1")

    # LDM: replace within list (index 2) -> re-sorts to {r1, r3, r4}.
    insn = linux_arm.one_insn_or_raise("ldm r0, {r1, r2, r3}")
    new_insn = insn.operands.replace(2, "r4")
    assert new_insn.operands.reg(1) == Arm.reg("r1")
    assert new_insn.operands.reg(2) == Arm.reg("r3")
    assert new_insn.operands.reg(3) == Arm.reg("r4")

    # Single-register list replacement.
    insn = linux_arm.one_insn_or_raise("pop {r0}")
    new_insn = insn.operands.replace(0, "r4")
    assert new_insn.operands.reg(0) == Arm.reg("r4")


# =============================================================================
# MIPS Mnemonic Normalization
# =============================================================================


def test_mips_mnemonic_normalization_imm_to_reg():
    Mips = Architectures.Mips.value
    linux_mips = Triple(Mips, Platform.Linux)

    # addiu to addu
    insn = linux_mips.one_insn_or_raise("addiu $at, $at, 100")
    insn = insn.operands.replace(-1, "s6")
    assert insn.mnemonic == "addu"
    assert insn.operands.reg(-1) == Mips.reg("s6")

    # ori to or
    insn = linux_mips.one_insn_or_raise("ori $t0, $t1, 0xff")
    insn = insn.operands.replace(-1, "t2")
    assert insn.mnemonic == "or"
    assert insn.operands.reg(-1) == Mips.reg("t2")

    # andi to and
    insn = linux_mips.one_insn_or_raise("andi $v0, $v1, 0x10")
    insn = insn.operands.replace(-1, "a0")
    assert insn.mnemonic == "and"
    assert insn.operands.reg(-1) == Mips.reg("a0")

    # xori to xor
    insn = linux_mips.one_insn_or_raise("xori $s0, $s1, 42")
    insn = insn.operands.replace(-1, "s2")
    assert insn.mnemonic == "xor"
    assert insn.operands.reg(-1) == Mips.reg("s2")


def test_mips_mnemonic_normalization_reg_to_imm():
    Mips = Architectures.Mips.value
    linux_mips = Triple(Mips, Platform.Linux)

    # addu to addiu
    insn = linux_mips.one_insn_or_raise("addu $t0, $t1, $t2")
    insn = insn.operands.replace(-1, 100)
    assert insn.mnemonic == "addiu"
    assert insn.operands.imm(-1) == 100

    # or to ori
    insn = linux_mips.one_insn_or_raise("or $v0, $v1, $a0")
    insn = insn.operands.replace(-1, 0xFF)
    assert insn.mnemonic == "ori"
    assert insn.operands.imm(-1) == 0xFF

    # and to andi
    insn = linux_mips.one_insn_or_raise("and $s0, $s1, $s2")
    insn = insn.operands.replace(-1, 0x10)
    assert insn.mnemonic == "andi"
    assert insn.operands.imm(-1) == 0x10

    # xor to xori
    insn = linux_mips.one_insn_or_raise("xor $a0, $a1, $a2")
    insn = insn.operands.replace(-1, 42)
    assert insn.mnemonic == "xori"
    assert insn.operands.imm(-1) == 42
