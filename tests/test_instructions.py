import pytest

from int3 import Architectures, Int3CodeGenerationError, MemoryOperand, Platform, Triple


def test_triple_insn_factory():
    x86_64 = Architectures.x86_64.value
    Mips = Architectures.Mips.value

    linux_x86_64 = Triple(x86_64, Platform.Linux)
    linux_mips = Triple(Mips, Platform.Linux)

    # x86_64 tests
    # ~~~~~~~~~~~~
    insns = linux_x86_64.insns(
        "\n".join(
            [
                "pop rdx",
                "syscall",
                "add rax, r15",
                "lea rdi, [rip+0x100]",
                "mov byte ptr [rax], 0x1",
                "call qword ptr [rsp-0x10]",
            ]
        )
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

    # lea rdi, [rip+0x100]
    assert insns[3].mnemonic == "lea"
    assert insns[3].is_mov()
    assert insns[3].op_str == "rdi, [rip + 0x100]"
    assert len(insns[3].operands) == 2
    assert insns[3].operands.is_reg(0)
    assert insns[3].operands.reg(0) == x86_64.reg("rdi")
    assert insns[3].operands.is_mem(1)
    assert insns[3].operands.mem(1) == MemoryOperand(x86_64.reg("rip"), 0x100)

    # mov byte ptr [rax], 0x1
    assert insns[4].mnemonic == "mov"
    assert insns[4].is_mov()
    assert len(insns[4].operands) == 2
    assert insns[4].operands.mem(0) == MemoryOperand(x86_64.reg("rax"), 0, "byte ptr")
    assert insns[4].operands.imm(1) == 1

    # call qword ptr [rsp-0x10]
    assert insns[5].mnemonic == "call"
    assert insns[5].is_call()
    assert len(insns[5].operands) == 1
    assert insns[5].operands.is_mem(0)
    assert insns[5].operands.mem(0) == MemoryOperand(
        x86_64.reg("rsp"), -0x10, "qword ptr"
    )

    # Mips tests
    # ~~~~~~~~~~
    insns = linux_mips.insns(
        "\n".join(
            [
                "lui $v0, 0xcafe",
                "ori $v0, $v0, 0xbeef",
                "add $a0, $zero, $v1",
                "syscall",
            ]
        )
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


def test_access_operand_out_of_bounds():
    linux_x86_64 = Triple(Architectures.x86_64.value, Platform.Linux)

    insn = linux_x86_64.one_insn_or_raise("mov eax, 123")
    with pytest.raises(Int3CodeGenerationError):
        insn.operands.replace(2, 0xBEEF)

    insn = linux_x86_64.one_insn_or_raise("syscall")
    with pytest.raises(Int3CodeGenerationError):
        insn.operands.reg(0)
    with pytest.raises(Int3CodeGenerationError):
        insn.operands.imm(-1)


def test_access_operand_via_negative_index():
    # TODO
    assert False


def test_patch_immediate_with_register():
    # TODO
    assert False


def test_memory_operand_str():
    x86_64 = Architectures.x86_64.value
    rax = x86_64.reg("rax")

    assert str(MemoryOperand(rax, 0xFF)) == "[rax + 0xff]"
    assert str(MemoryOperand(rax, 0)) == "[rax]"
    assert str(MemoryOperand(rax, 0)) == "[rax]"
