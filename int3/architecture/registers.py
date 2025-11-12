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

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} [{self.name}:{self.bit_size}]>"

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
    eip = RegisterDef(name="eip", bit_size=32)

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


class ArmRegisters:
    r0 = RegisterDef(name="r0", bit_size=32)
    r1 = RegisterDef(name="r1", bit_size=32)
    r2 = RegisterDef(name="r2", bit_size=32)
    r3 = RegisterDef(name="r3", bit_size=32)
    r4 = RegisterDef(name="r4", bit_size=32)
    r5 = RegisterDef(name="r5", bit_size=32)
    r6 = RegisterDef(name="r6", bit_size=32)
    r7 = RegisterDef(name="r7", bit_size=32)
    r8 = RegisterDef(name="r8", bit_size=32)
    r9 = RegisterDef(name="r9", bit_size=32)
    r10 = RegisterDef(name="r10", bit_size=32)
    r11 = RegisterDef(name="r11", bit_size=32)
    r12 = RegisterDef(name="r12", bit_size=32)
    r13 = RegisterDef(name="r13", bit_size=32)
    r14 = RegisterDef(name="r14", bit_size=32)
    r15 = RegisterDef(name="r15", bit_size=32)

    fp = RegisterDef(name="fp", bit_size=32)  # Frame pointer (r11)
    sp = RegisterDef(name="sp", bit_size=32)  # Stack pointer (r13)
    lr = RegisterDef(name="lr", bit_size=32)  # Link register (r14)
    pc = RegisterDef(name="pc", bit_size=32)  # Program counter (r15)


class Aarch64Registers:
    x0 = RegisterDef(name="x0", bit_size=64)
    x1 = RegisterDef(name="x1", bit_size=64)
    x2 = RegisterDef(name="x2", bit_size=64)
    x3 = RegisterDef(name="x3", bit_size=64)
    x4 = RegisterDef(name="x4", bit_size=64)
    x5 = RegisterDef(name="x5", bit_size=64)
    x6 = RegisterDef(name="x6", bit_size=64)
    x7 = RegisterDef(name="x7", bit_size=64)
    x8 = RegisterDef(name="x8", bit_size=64)
    x9 = RegisterDef(name="x9", bit_size=64)
    x10 = RegisterDef(name="x10", bit_size=64)
    x11 = RegisterDef(name="x11", bit_size=64)
    x12 = RegisterDef(name="x12", bit_size=64)
    x13 = RegisterDef(name="x13", bit_size=64)
    x14 = RegisterDef(name="x14", bit_size=64)
    x15 = RegisterDef(name="x15", bit_size=64)
    x16 = RegisterDef(name="x16", bit_size=64)
    x17 = RegisterDef(name="x17", bit_size=64)
    x18 = RegisterDef(name="x18", bit_size=64)
    x19 = RegisterDef(name="x19", bit_size=64)
    x20 = RegisterDef(name="x20", bit_size=64)
    x21 = RegisterDef(name="x21", bit_size=64)
    x22 = RegisterDef(name="x22", bit_size=64)
    x23 = RegisterDef(name="x23", bit_size=64)
    x24 = RegisterDef(name="x24", bit_size=64)
    x25 = RegisterDef(name="x25", bit_size=64)
    x26 = RegisterDef(name="x26", bit_size=64)
    x27 = RegisterDef(name="x27", bit_size=64)
    x28 = RegisterDef(name="x28", bit_size=64)
    x29 = RegisterDef(name="x29", bit_size=64)
    x30 = RegisterDef(name="x30", bit_size=64)

    # 32-bit register views (w0-w30)
    w0 = RegisterDef(name="w0", bit_size=32)
    w1 = RegisterDef(name="w1", bit_size=32)
    w2 = RegisterDef(name="w2", bit_size=32)
    w3 = RegisterDef(name="w3", bit_size=32)
    w4 = RegisterDef(name="w4", bit_size=32)
    w5 = RegisterDef(name="w5", bit_size=32)
    w6 = RegisterDef(name="w6", bit_size=32)
    w7 = RegisterDef(name="w7", bit_size=32)
    w8 = RegisterDef(name="w8", bit_size=32)
    w9 = RegisterDef(name="w9", bit_size=32)
    w10 = RegisterDef(name="w10", bit_size=32)
    w11 = RegisterDef(name="w11", bit_size=32)
    w12 = RegisterDef(name="w12", bit_size=32)
    w13 = RegisterDef(name="w13", bit_size=32)
    w14 = RegisterDef(name="w14", bit_size=32)
    w15 = RegisterDef(name="w15", bit_size=32)
    w16 = RegisterDef(name="w16", bit_size=32)
    w17 = RegisterDef(name="w17", bit_size=32)
    w18 = RegisterDef(name="w18", bit_size=32)
    w19 = RegisterDef(name="w19", bit_size=32)
    w20 = RegisterDef(name="w20", bit_size=32)
    w21 = RegisterDef(name="w21", bit_size=32)
    w22 = RegisterDef(name="w22", bit_size=32)
    w23 = RegisterDef(name="w23", bit_size=32)
    w24 = RegisterDef(name="w24", bit_size=32)
    w25 = RegisterDef(name="w25", bit_size=32)
    w26 = RegisterDef(name="w26", bit_size=32)
    w27 = RegisterDef(name="w27", bit_size=32)
    w28 = RegisterDef(name="w28", bit_size=32)
    w29 = RegisterDef(name="w29", bit_size=32)
    w30 = RegisterDef(name="w30", bit_size=32)

    fp = RegisterDef(name="fp", bit_size=64)  # Frame pointer (x29)
    sp = RegisterDef(name="sp", bit_size=64)  # Stack pointer
    lr = RegisterDef(name="lr", bit_size=64)  # Link register (x30)
    xzr = RegisterDef(name="xzr", bit_size=64)  # Zero register (64-bit)
    wzr = RegisterDef(name="wzr", bit_size=32)  # Zero register (32-bit)


class Registers:
    """Primary interface for accessing architecture-specific register sets.

    .. doctest::

        >>> from int3 import Registers
        >>> Registers.x86.eax
        RegisterDef(name='eax', bit_size=32, llvm_alt_name=None)
        >>> Registers.Mips.a0
        RegisterDef(name='a0', bit_size=32, llvm_alt_name='4')

    """

    x86_64 = x86_64Registers
    x86 = x86Registers
    Mips = MipsRegisters
    Arm = ArmRegisters
    Aarch64 = Aarch64Registers
