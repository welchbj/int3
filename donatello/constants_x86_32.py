"""Relevant constants for the x86 32-bit instruction set."""

#
# Some useful references:
#   - reg-clearing techniques: https://stackoverflow.com/a/32673696/5094008
#   - detailed discussion of ^: https://stackoverflow.com/a/33668295/5094008
#

from collections import (
    namedtuple)


Gadget = namedtuple('Gadget', ['shellcode', 'asm'])

IMPLEMENTED_OPS = ('and', 'or', 'xor',)

# int constants
NUM_BITS_IN_BYTE = 8
NUM_BITS_IN_DWORD = 32

# gadgets for pushing eax onto the stack
PUSH_EAX_GADGETS = [
    Gadget(b'\x50', 'push eax'),
    # TODO
]

# gadgets for pushing esp onto the stack
PUSH_ESP_GADGETS = [
    Gadget(b'\x54', 'push esp'),
    # TODO
]

# gadgets for popping from the stack into eax
POP_EAX_GADGETS = [
    Gadget(b'\x58', 'pop eax'),
    # TODO
]

# gadgets for popping from the stack into esp
POP_ESP_GADGETS = [
    Gadget(b'\x5c', 'pop esp'),
    # TODO
]

# gadgets for clearing eax
CLEAR_EAX_GADGETS = [
    Gadget(b'\x31\xc0', 'xor eax,eax'),
    # TODO
]

# effective nops
NOPS = [
    Gadget(b'\x90', 'nop'),
    Gadget(b'\x40', 'inc eax'),
    Gadget(b'\x43', 'inc ebx'),
    Gadget(b'\x41', 'inc ecx'),
    Gadget(b'\x42', 'inc edx'),
    Gadget(b'\x46', 'inc esi'),
    Gadget(b'\x47', 'inc edi'),
    Gadget(b'\x48', 'dec eax'),
    Gadget(b'\x4b', 'dec ebx'),
    Gadget(b'\x49', 'dec ecx'),
    Gadget(b'\x4a', 'dec edx'),
    Gadget(b'\x4e', 'dec esi'),
    Gadget(b'\x4f', 'dec edi'),
]

# gadgets for stack sculpting via eax
OR_EAX_GADGETS = [
    Gadget(b'\x0d', 'or eax,dword {}'),
    # TODO
]

AND_EAX_GADGETS = [
    Gadget(b'\x25', 'and eax,dword {}'),
    # TODO
]

SUB_EAX_GADGETS = [
    Gadget(b'\x2d', 'sub eax, dword {}'),
    # TODO
]

XOR_EAX_GADGETS = [
    Gadget(b'\x35', 'xor eax,dword {}'),
    # TODO
]

ADD_EAX_GADGETS = [
    Gadget(b'\x05', 'add eax,dword {}'),
    # TODO
]
