from typing import Literal, TypeAlias, TypeVar

IntImmediate: TypeAlias = int
BytesImmediate: TypeAlias = bytes
Immediate: TypeAlias = int | bytes

# Annotate general purpose registers per architecture.
x86Registers = Literal["eax", "ebx", "ecx", "edx", "esi", "edi", "edi", "ebp", "esp"]
x86_64Registers = Literal[
    "rax",
    "rbx",
    "rcx",
    "rdx",
    "rbp",
    "rsp",
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

# TODO: Add 8-, 16-, and 32-bit width variants where applicable.

Registers = TypeVar("Registers", x86Registers, x86_64Registers)
