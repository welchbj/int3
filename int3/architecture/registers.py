from dataclasses import dataclass


@dataclass(frozen=True)
class RegisterDef:
    """Metadata for an architecture's specific register.

    .. doctest::

        >>> from int3 import Registers
        >>> Registers.Mips.zero
        RegisterDef(name='zero', bit_size=32, llvm_alt_name='0')

    """

    name: str
    bit_size: int
    llvm_alt_name: str | None = None

    def __str__(self) -> str:
        return self.name

    @property
    def llvm_name(self) -> str:
        if self.llvm_alt_name is None:
            return self.name
        else:
            return self.llvm_alt_name


class x86_64Registers:
    rip = RegisterDef(name="rip", bit_size=64)

    rsp = RegisterDef(name="rsp", bit_size=64)
    esp = RegisterDef(name="esp", bit_size=32)
    sp = RegisterDef(name="sp", bit_size=16)
    spl = RegisterDef(name="spl", bit_size=8)

    rbp = RegisterDef(name="rbp", bit_size=64)
    ebp = RegisterDef(name="ebp", bit_size=32)
    bp = RegisterDef(name="bp", bit_size=16)
    bpl = RegisterDef(name="bpl", bit_size=8)

    rax = RegisterDef(name="rax", bit_size=64)
    eax = RegisterDef(name="eax", bit_size=32)
    ax = RegisterDef(name="ax", bit_size=16)
    al = RegisterDef(name="al", bit_size=8)

    rbx = RegisterDef(name="rbx", bit_size=64)
    ebx = RegisterDef(name="ebx", bit_size=32)
    bx = RegisterDef(name="bx", bit_size=16)
    bl = RegisterDef(name="bl", bit_size=8)

    rcx = RegisterDef(name="rcx", bit_size=64)
    ecx = RegisterDef(name="ecx", bit_size=32)
    cx = RegisterDef(name="cx", bit_size=16)
    cl = RegisterDef(name="cl", bit_size=8)

    rdx = RegisterDef(name="rdx", bit_size=64)
    edx = RegisterDef(name="edx", bit_size=32)
    dx = RegisterDef(name="dx", bit_size=16)
    dl = RegisterDef(name="dl", bit_size=8)

    rdi = RegisterDef(name="rdi", bit_size=64)
    edi = RegisterDef(name="edi", bit_size=32)
    di = RegisterDef(name="di", bit_size=16)
    dil = RegisterDef(name="dil", bit_size=8)

    rsi = RegisterDef(name="rsi", bit_size=64)
    esi = RegisterDef(name="esi", bit_size=32)
    si = RegisterDef(name="si", bit_size=16)
    sil = RegisterDef(name="sil", bit_size=8)

    r8 = RegisterDef(name="r8", bit_size=64)
    r8d = RegisterDef(name="r8d", bit_size=32)
    r8w = RegisterDef(name="r8w", bit_size=16)
    r8b = RegisterDef(name="r8b", bit_size=8)

    r9 = RegisterDef(name="r9", bit_size=64)
    r9d = RegisterDef(name="r9d", bit_size=32)
    r9w = RegisterDef(name="r9w", bit_size=16)
    r9b = RegisterDef(name="r9b", bit_size=8)

    r10 = RegisterDef(name="r10", bit_size=64)
    r10d = RegisterDef(name="r10d", bit_size=32)
    r10w = RegisterDef(name="r10w", bit_size=16)
    r10b = RegisterDef(name="r10b", bit_size=8)

    r11 = RegisterDef(name="r11", bit_size=64)
    r11d = RegisterDef(name="r11d", bit_size=32)
    r11w = RegisterDef(name="r11w", bit_size=16)
    r11b = RegisterDef(name="r11b", bit_size=8)

    r12 = RegisterDef(name="r12", bit_size=64)
    r12d = RegisterDef(name="r12d", bit_size=32)
    r12w = RegisterDef(name="r12w", bit_size=16)
    r12b = RegisterDef(name="r12b", bit_size=8)

    r13 = RegisterDef(name="r13", bit_size=64)
    r13d = RegisterDef(name="r13d", bit_size=32)
    r13w = RegisterDef(name="r13w", bit_size=16)
    r13b = RegisterDef(name="r13b", bit_size=8)

    r14 = RegisterDef(name="r14", bit_size=64)
    r14d = RegisterDef(name="r14d", bit_size=32)
    r14w = RegisterDef(name="r14w", bit_size=16)
    r14b = RegisterDef(name="r14b", bit_size=8)

    r15 = RegisterDef(name="r15", bit_size=64)
    r15d = RegisterDef(name="r15d", bit_size=32)
    r15w = RegisterDef(name="r15w", bit_size=16)
    r15b = RegisterDef(name="r15b", bit_size=8)


class x86Registers:
    eip = RegisterDef(name="rip", bit_size=32)

    esp = RegisterDef(name="esp", bit_size=32)
    sp = RegisterDef(name="sp", bit_size=16)
    spl = RegisterDef(name="spl", bit_size=8)

    ebp = RegisterDef(name="ebp", bit_size=32)
    bp = RegisterDef(name="bp", bit_size=16)
    bpl = RegisterDef(name="bpl", bit_size=8)

    eax = RegisterDef(name="eax", bit_size=32)
    ax = RegisterDef(name="ax", bit_size=16)
    al = RegisterDef(name="al", bit_size=8)

    ebx = RegisterDef(name="ebx", bit_size=32)
    bx = RegisterDef(name="bx", bit_size=16)
    bl = RegisterDef(name="bl", bit_size=8)

    ecx = RegisterDef(name="ecx", bit_size=32)
    cx = RegisterDef(name="cx", bit_size=16)
    cl = RegisterDef(name="cl", bit_size=8)

    edx = RegisterDef(name="edx", bit_size=32)
    dx = RegisterDef(name="dx", bit_size=16)
    dl = RegisterDef(name="dl", bit_size=8)

    esi = RegisterDef(name="esi", bit_size=32)
    si = RegisterDef(name="si", bit_size=16)
    sil = RegisterDef(name="sil", bit_size=8)

    edi = RegisterDef(name="edi", bit_size=32)
    di = RegisterDef(name="di", bit_size=16)
    dil = RegisterDef(name="dil", bit_size=8)


class MipsRegisters:
    # llvm_alt_name values are populated from the Registers section of:
    # https://github.com/llvm/llvm-project/blob/main/llvm/lib/Target/Mips/MipsRegisterInfo.td

    zero = RegisterDef(name="zero", bit_size=32, llvm_alt_name="0")
    at = RegisterDef(name="at", bit_size=32, llvm_alt_name="1")
    gp = RegisterDef(name="gp", bit_size=32, llvm_alt_name="28")
    sp = RegisterDef(name="sp", bit_size=32, llvm_alt_name="29")
    fp = RegisterDef(name="fp", bit_size=32, llvm_alt_name="30")
    ra = RegisterDef(name="ra", bit_size=32, llvm_alt_name="31")

    v0 = RegisterDef(name="v0", bit_size=32, llvm_alt_name="2")
    v1 = RegisterDef(name="v1", bit_size=32, llvm_alt_name="3")
    a0 = RegisterDef(name="a0", bit_size=32, llvm_alt_name="4")
    a1 = RegisterDef(name="a1", bit_size=32, llvm_alt_name="5")
    a2 = RegisterDef(name="a2", bit_size=32, llvm_alt_name="6")
    a3 = RegisterDef(name="a3", bit_size=32, llvm_alt_name="7")
    t0 = RegisterDef(name="t0", bit_size=32, llvm_alt_name="8")
    t1 = RegisterDef(name="t1", bit_size=32, llvm_alt_name="9")
    t2 = RegisterDef(name="t2", bit_size=32, llvm_alt_name="10")
    t3 = RegisterDef(name="t3", bit_size=32, llvm_alt_name="11")
    t4 = RegisterDef(name="t4", bit_size=32, llvm_alt_name="12")
    t5 = RegisterDef(name="t5", bit_size=32, llvm_alt_name="13")
    t6 = RegisterDef(name="t6", bit_size=32, llvm_alt_name="14")
    t7 = RegisterDef(name="t7", bit_size=32, llvm_alt_name="15")
    t8 = RegisterDef(name="t8", bit_size=32, llvm_alt_name="24")
    t9 = RegisterDef(name="t9", bit_size=32, llvm_alt_name="25")
    s0 = RegisterDef(name="s0", bit_size=32, llvm_alt_name="16")
    s1 = RegisterDef(name="s1", bit_size=32, llvm_alt_name="17")
    s2 = RegisterDef(name="s2", bit_size=32, llvm_alt_name="18")
    s3 = RegisterDef(name="s3", bit_size=32, llvm_alt_name="19")
    s4 = RegisterDef(name="s4", bit_size=32, llvm_alt_name="20")
    s5 = RegisterDef(name="s5", bit_size=32, llvm_alt_name="21")
    s6 = RegisterDef(name="s6", bit_size=32, llvm_alt_name="22")
    s7 = RegisterDef(name="s7", bit_size=32, llvm_alt_name="23")
    t8 = RegisterDef(name="t8", bit_size=32, llvm_alt_name="24")
    t9 = RegisterDef(name="t9", bit_size=32, llvm_alt_name="25")
    k0 = RegisterDef(name="k0", bit_size=32, llvm_alt_name="26")
    k1 = RegisterDef(name="k1", bit_size=32, llvm_alt_name="27")


class Registers:
    """Primary interface for accessing architecture-specific register sets."""
    x86_64 = x86_64Registers
    x86 = x86Registers
    Mips = MipsRegisters
