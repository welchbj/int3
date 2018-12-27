"""Functionality for encoding a payload, excluding specified bad characters."""

from collections import (
    OrderedDict)
from struct import (
    unpack)

from .chars import (
    first_valid_gadget)
from .constants_x86_32 import (
    AND_EAX_GADGETS,
    CLEAR_EAX_GADGETS,
    OR_EAX_GADGETS,
    POP_EAX_GADGETS,
    POP_ESP_GADGETS,
    PUSH_EAX_GADGETS,
    PUSH_ESP_GADGETS,
    NOPS,
    XOR_EAX_GADGETS)
from .errors import (
    DonatelloCannotEncodeError,
    DonatelloNoPossibleNopsError)
from .factor_32 import (
    factor_and,
    factor_or,
    factor_xor)
from .utils import (
    chunked)


def factors_to_asm(factors, asm_template):
    """Convert a set of factors into a usable assembly snippet.

    Args:
        factors (List[int]): The list of factors that compose the chain of
            operands needed to build the intended value.
        asm_template (str): The format string in which factors will be
            injected.

    Returns:
        List[str]: The sequence of assembly instructions that will combine the
            factors into our intended target value.

    """
    return [asm_template.format(hex(factor)) for factor in factors]


def stack_pack_32(word):
    """Pack 4 bytes into a 32-bit integer to be pushed onto the stack.

    This essentially packs the the four-byte word into an integer, with the
    bytes in the reverse order as passed to this function.

    Args:
        word (bytes or bytearray): The four bytes to pack.

    Returns:
        int: The packed word, as the integer we intend to push onto the stack.

    Raises:
        TODO

    """
    word = bytearray(word)
    if len(word) != 4:
        # TODO
        pass

    ret, = unpack('<I', word)
    return ret


def chunked_payload_32(payload, nop):
    """Nop-align and divide a payload into packed 4-byte chunks.

    This function will build each 4-byte chunk into a packed 4-byte integer.
    This integer is the value we want to push onto the stack to represent our
    instruction.

    Args:
        payload (bytes or bytearray): The raw, not-necessarily-padded payload
            to chunk and pack.
        nop (bytes): The single-byte nop to use in padding.

    Returns:
        List[int]: The list of 32-bit integers comprising our packed payload.

    Raises:
        TODO

    """
    payload = bytearray(payload)

    if len(nop) != 1:
        # TODO
        pass

    # pad to be divisible into 4-byte chunks
    mod = len(payload) % 4
    if mod:
        payload += (4 - mod) * nop

    # divide into 4-byte chunks
    chunks = list(chunked(payload, 4))

    # iterate over chunks in reverse order
    packed_chunks = [stack_pack_32(chunk) for chunk in reversed(chunks)]
    return packed_chunks


def encode_x86_32(payload, bad_chars, align=False, force=False):
    """Encode a payload into x86 assembly, excluding the specified characters.

    Args:
        TODO

    Returns:
        str: The source (in Intel syntax) of an assembly program that will
            push the specified payload onto the stack, excluding the given
            bad characters.

    Raises:
        DonatelloNoPossibleNopsError: When no the bad character set restricts
            all nops from being used.

    """
    payload = bytearray(payload)
    bad_chars = bytearray(bad_chars)

    # handle case where no bad characters exist in the payload
    if not force:
        num_bad_char_occurrences = sum(payload.count(bc) for bc in bad_chars)
        if not num_bad_char_occurrences:
            raise (  # TODO
                'No bad characters appear in the specified payload; use the '
                '`force` kwarg to bypass this check')

    # determine our valid nop instruction
    for candidate in NOPS:
        if candidate.shellcode not in bad_chars:
            nop = candidate
            break
    else:
        raise DonatelloNoPossibleNopsError(
            'Specified bad character set restricts all configured nops')

    targets = chunked_payload_32(payload, nop.shellcode)

    # find a valid method for pushing eax on the stack
    push_eax = first_valid_gadget(PUSH_EAX_GADGETS, bad_chars)
    if push_eax is None:
        raise DonatelloCannotEncodeError(
            'Bad character set restricts all configured `push eax` gadgets')
    push_eax_asm = push_eax.asm

    # determine valid builder gadgets
    or_eax = first_valid_gadget(OR_EAX_GADGETS, bad_chars)
    and_eax = first_valid_gadget(AND_EAX_GADGETS, bad_chars)
    xor_eax = first_valid_gadget(XOR_EAX_GADGETS, bad_chars)

    # find a valid method for clearing eax
    clear_eax = first_valid_gadget(CLEAR_EAX_GADGETS, bad_chars)
    if clear_eax is not None:
        clear_eax_asm = clear_eax.asm
    elif and_eax is not None:
        # TODO
        pass
    elif xor_eax is not None:
        # TODO
        pass
    else:
        raise DonatelloCannotEncodeError(
            'Bad character set restricts all methods of clearing eax')

    # setup factorization dict
    factor_mapping = OrderedDict()
    if or_eax is not None:
        factor_mapping[or_eax] = factor_or
    if and_eax is not None:
        factor_mapping[and_eax] = factor_and
    if xor_eax is not None:
        factor_mapping[xor_eax] = factor_xor

    # determine factors for each target
    asm = []
    bad_chars_as_ints = tuple(int(bc) for bc in bad_chars)
    for target in targets:
        asm.append(clear_eax_asm)
        for gadget, factor_func in factor_mapping.items():
            factors = factor_func(target, bad_chars_as_ints)
            if factors is not None:
                asm.extend(factors_to_asm(factors, gadget.asm))
                break
        else:
            raise DonatelloCannotEncodeError(
                'Unable to encode target value ' + hex(target))
        asm.append(push_eax_asm)

    if align:
        # TODO
        # need to compute gadgets for `push esp` and `pop eax`
        pass

    return '\n'.join(asm)
