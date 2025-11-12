from int3.architecture import Architecture, Architectures, Registers
from int3.codegen import CodeGenerator, Segment
from int3.platform import Platform, Triple

from .qemu import parametrize_qemu_arch


def test_register_expansion():
    x86_64 = Architectures.x86_64.value
    rax = x86_64.reg("rax")
    expanded_regs = x86_64.expand_regs(rax)
    expected_regs = (
        Registers.x86_64.rax,
        Registers.x86_64.eax,
        Registers.x86_64.al,
        Registers.x86_64.ax,
    )
    assert len(expanded_regs) == len(expected_regs)
    assert set(expanded_regs) == set(expected_regs)

    mips = Architectures.Mips.value
    a0 = mips.reg("a0")
    assert mips.expand_regs(a0) == (a0,)


def test_register_equivalence():
    x86_64 = Architectures.x86_64.value
    assert x86_64.reg("rax") == x86_64.reg("rax")
    assert x86_64.reg("rax") == Registers.x86_64.rax


def test_register_def_str_methods():
    mips = Architectures.Mips.value
    assert str(mips.reg("v0")) == "v0"
    assert repr(mips.reg("v0")) == "<RegisterDef [v0:32]>"


def test_arithmetic_tainted_register_resolution():
    x86_64 = Architectures.x86_64.value
    linux_x86_64 = Triple(x86_64, Platform.Linux)
    segment = Segment.from_asm(
        triple=linux_x86_64,
        asm="""
        mov rax, 0xdead
        inc bx
        add r15, r10
        jne label
    label:
    """,
    )
    assert len(segment.insns) == 4
    all_tainted_regs = set()
    assert segment.insns[0].tainted_regs == set(x86_64.expand_regs("rax"))
    all_tainted_regs |= set(x86_64.expand_regs("rax"))
    assert segment.insns[1].tainted_regs == set(x86_64.expand_regs("bx"))
    all_tainted_regs |= set(x86_64.expand_regs("bx"))
    assert segment.insns[2].tainted_regs == set(x86_64.expand_regs("r15"))
    all_tainted_regs |= set(x86_64.expand_regs("r15"))
    assert segment.insns[3].tainted_regs == set()
    assert segment.tainted_regs == all_tainted_regs

    mips = Architectures.Mips.value
    linux_mips = Triple(mips, Platform.Linux)
    segment = Segment.from_asm(
        triple=linux_mips,
        asm="""
        ori $at, $zero, 0xbeef
        addu $a0, $at, $v0
        addiu $v0, $zero, 0xfa1
        jr $ra
    """,
    )
    # There is an extra instruction for the implicit NOP that Keystone adds
    # after the jr instruction.
    assert len(segment.insns) == 5
    all_tainted_regs = set()
    assert segment.insns[0].tainted_regs == {mips.reg("at")}
    all_tainted_regs.add(mips.reg("at"))
    assert segment.insns[1].tainted_regs == {mips.reg("a0")}
    all_tainted_regs.add(mips.reg("a0"))
    assert segment.insns[2].tainted_regs == {mips.reg("v0")}
    all_tainted_regs.add(mips.reg("v0"))
    assert segment.insns[3].tainted_regs == set()
    assert segment.tainted_regs == all_tainted_regs


@parametrize_qemu_arch
def test_linux_syscall_tainted_register_resolution(arch: Architecture):
    triple = Triple(arch, Platform.Linux)
    codegen = CodeGenerator(triple)
    segment = codegen.syscall().choose()

    # The syscall result register should always be tainted.
    expected_result_regs = set(arch.expand_regs(triple.syscall_convention.result))
    assert expected_result_regs.issubset(segment.tainted_regs)

    if arch.name in ("arm", "aarch64"):
        # For ARM architectures, the syscall instruction may also taint the
        # link register.
        expected_lr_regs = set(arch.expand_regs(arch.reg("lr")))
        assert expected_lr_regs.issubset(segment.tainted_regs)

        expected_all_regs = expected_result_regs | expected_lr_regs
        assert segment.tainted_regs == expected_all_regs
    else:
        # For other architectures, only the result register should be tainted.
        assert segment.tainted_regs == expected_result_regs


def test_expanded_reserved_regs():
    """Test that expanded_reserved_regs includes expected register aliases."""
    x86_64 = Architectures.x86_64.value
    assert Registers.x86_64.rsp in x86_64.expanded_reserved_regs
    assert Registers.x86_64.esp in x86_64.expanded_reserved_regs
    assert Registers.x86_64.sp in x86_64.expanded_reserved_regs
    assert Registers.x86_64.spl in x86_64.expanded_reserved_regs
    assert Registers.x86_64.rip in x86_64.expanded_reserved_regs

    arm = Architectures.Arm.value
    assert Registers.Arm.sp in arm.expanded_reserved_regs
    assert Registers.Arm.r13 in arm.expanded_reserved_regs
    assert Registers.Arm.pc in arm.expanded_reserved_regs
    assert Registers.Arm.r15 in arm.expanded_reserved_regs

    aarch64 = Architectures.Aarch64.value
    assert Registers.Aarch64.sp in aarch64.expanded_reserved_regs
    assert Registers.Aarch64.xzr in aarch64.expanded_reserved_regs
    assert Registers.Aarch64.wzr in aarch64.expanded_reserved_regs

