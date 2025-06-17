from dataclasses import dataclass


@dataclass(frozen=True)
class RegisterDef:
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
    rsp = RegisterDef(name="rsp", bit_size=64)
    rbp = RegisterDef(name="rbp", bit_size=64)

    rax = RegisterDef(name="rax", bit_size=64)
    rbx = RegisterDef(name="rbx", bit_size=64)
    rcx = RegisterDef(name="rcx", bit_size=64)
    rdx = RegisterDef(name="rdx", bit_size=64)
    rdi = RegisterDef(name="rdi", bit_size=64)
    rsi = RegisterDef(name="rsi", bit_size=64)
    r8 = RegisterDef(name="r8", bit_size=64)
    r9 = RegisterDef(name="r9", bit_size=64)
    r10 = RegisterDef(name="r10", bit_size=64)
    r11 = RegisterDef(name="r11", bit_size=64)
    r12 = RegisterDef(name="r12", bit_size=64)
    r13 = RegisterDef(name="r13", bit_size=64)
    r14 = RegisterDef(name="r14", bit_size=64)
    r15 = RegisterDef(name="r15", bit_size=64)


class x86Registers:
    esp = RegisterDef(name="esp", bit_size=32)
    ebp = RegisterDef(name="ebp", bit_size=32)

    eax = RegisterDef(name="eax", bit_size=32)
    ebx = RegisterDef(name="ebx", bit_size=32)
    ecx = RegisterDef(name="ecx", bit_size=32)
    edx = RegisterDef(name="edx", bit_size=32)
    esi = RegisterDef(name="esi", bit_size=32)
    edi = RegisterDef(name="edi", bit_size=32)


class MipsRegisters:
    # llvm_alt_name values are populated from the Registers section of:
    # https://github.com/llvm/llvm-project/blob/main/llvm/lib/Target/Mips/MipsRegisterInfo.td

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
    x86_64 = x86_64Registers
    x86 = x86Registers
    Mips = MipsRegisters
