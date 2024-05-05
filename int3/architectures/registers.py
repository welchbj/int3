#
# x86 registers.
#
x86GpRegisters = ("eax", "ebx", "ecx", "edx", "esi", "edi", "edi", "ebp")
x86Registers = x86GpRegisters + ("eip", "esp")


#
# x86_64 registers.
#
x86_64GpRegisters = (
    "rax",
    "rbx",
    "rcx",
    "rdx",
    "rbp",
    "rsi",
    "rdi",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
)
x86_64Registers = x86_64GpRegisters + ("rip", "rsp")


#
# mips registers
#
MipsGpRegisters = (
    "$v0",
    "$v1",
    "$a0",
    "$a1",
    "$a2",
    "$a3",
    "$t0",
    "$t1",
    "$t2",
    "$t3",
    "$t4",
    "$t5",
    "$t6",
    "$t7",
    "$s0",
    "$s1",
    "$s2",
    "$s3",
    "$s4",
    "$s5",
    "$s6",
    "$s7",
    "$t8",
    "$t9",
    "$fp",
)
MipsRegisters = MipsGpRegisters + (
    "$zero",
    "$at",
    "$gp",
    "$sp",
    "$ra",
    "k0",
    "k1",
)
