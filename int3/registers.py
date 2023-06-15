from typing import Literal, TypeAlias, TypeVar

IntImmediate: TypeAlias = int
BytesImmediate: TypeAlias = bytes
Immediate: TypeAlias = int | bytes

# Registers annotated per architecture.
x86GpRegisters = Literal["eax", "ebx", "ecx", "edx", "esi", "edi", "edi", "ebp"]
x86Registers = Literal[x86GpRegisters, "eip", "esp"]

x86_64GpRegisters = Literal[
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
]
x86_64Registers = Literal[x86_64GpRegisters, "rip", "rsp"]


# TODO: Add 8-, 16-, and 32-bit width variants where applicable.


Registers = TypeVar("Registers", x86Registers, x86_64Registers)
