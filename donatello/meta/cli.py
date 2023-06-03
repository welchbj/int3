"""Command-line interface for `donatello`."""

# TODO: this is all broken

from __future__ import print_function

import sys

from argparse import (
    ArgumentParser,
    RawTextHelpFormatter)
from colorama import (
    init as init_colorama)

from ._version import (
    __version__)
from .constants_x86_32 import (
    IMPLEMENTED_OPS)
from .encode import (
    encode_x86_32)
from .errors import (
    DonatelloCannotEncodeError,
    DonatelloConfigurationError,
    DonatelloError,
    DonatelloNoPossibleNopsError,
    DonatelloNoPresentBadCharactersError)
from .factor_32 import (
    factor_by_byte)
from .io import (
    format_dword,
    print_e,
    print_i,
    print_w)


def get_parsed_args(args=None):
    """Get the parsed command-line arguments."""
    parser = ArgumentParser(
        prog='donatello',
        usage='donatello [OPTIONS] <factor|encode> target',
        description=(
            '████████▄   ▄██████▄  ███▄▄▄▄      ▄████████     ███        ▄████████  ▄█        ▄█        ▄██████▄\n'   # noqa
            '███   ▀███ ███    ███ ███▀▀▀██▄   ███    ███ ▀█████████▄   ███    ███ ███       ███       ███    ███\n'  # noqa
            '███    ███ ███    ███ ███   ███   ███    ███    ▀███▀▀██   ███    █▀  ███       ███       ███    ███\n'  # noqa
            '███    ███ ███    ███ ███   ███   ███    ███     ███   ▀  ▄███▄▄▄     ███       ███       ███    ███\n'  # noqa
            '███    ███ ███    ███ ███   ███ ▀███████████     ███     ▀▀███▀▀▀     ███       ███       ███    ███\n'  # noqa
            '███    ███ ███    ███ ███   ███   ███    ███     ███       ███    █▄  ███       ███       ███    ███\n'  # noqa
            '███   ▄███ ███    ███ ███   ███   ███    ███     ███       ███    ███ ███▌    ▄ ███▌    ▄ ███    ███\n'  # noqa
            '████████▀   ▀██████▀   ▀█   █▀    ███    █▀     ▄████▀     ██████████ █████▄▄██ █████▄▄██  ▀██████▀\n'   # noqa
            '\n'
            '                   sculpt the stack when facing restrictive bad character sets'),  # noqa
        formatter_class=RawTextHelpFormatter)

    # TODO: -a/--align option

    parser.add_argument(
        '-b', '--bad-chars',
        action='store',
        metavar='',
        help='bad characters in the format `\\x00\\x01` that cannot be\n'
             'present in the factored/encoded result')

    # TODO: -f/--force option

    # TODO: -s/--start-value for `factor`

    # TODO: specify output format / syntax

    parser.add_argument(
        '-m', '--max-factors',
        action='store',
        metavar='',
        help='the maximum number of factors used to generate each portion of\n'
             'the target value or payload')

    # TODO: -q/--quiet option

    parser.add_argument(
        '-o', '--ops',
        action='store',
        metavar='',
        help='comma-delimited list of operations permitted to be used when\n'
             'factoring (`or`, `and`, `xor`, etc.); defaults to all\n'
             'implemented x86 arithmetic operations not violating the bad\n'
             'character set and only applies when the command is set to\n'
             '`factor`')

    parser.add_argument(
        '--version',
        action='version',
        version=str(__version__),
        help='program version')

    parser.add_argument(
        'command',
        action='store',
        metavar='<factor|encode>',
        help='the action to perform; either `factor` or `encode`')

    parser.add_argument(
        'target',
        action='store',
        metavar='target',
        help='the value on which to perform the specified command: a hex\n'
             'value for `factor` and C/Python-formatted shellcode for\n'
             '`encode`; use `-` to specify the value on stdin')

    if args is None:
        args = sys.argv[1:]

    return parser.parse_args(args)


def _parse_bytes(byte_str_literal, check_dups=False):
    """Parse a byte string literal into a bytearray."""
    _cache = set()
    parsed = []
    for bc in byte_str_literal.split('\\x')[1:]:
        try:
            parsed_bc = int(bc, base=16)
            if parsed_bc < 0 or parsed_bc > 255:
                raise ValueError
            elif check_dups and parsed_bc in _cache:
                print_w('`\\x', bc, '` is present multiple times in your '
                        '-b/--bad-chars argument')
                continue
            parsed.append(parsed_bc)
            _cache.add(parsed_bc)
        except ValueError:
            raise DonatelloConfigurationError(
                'invalid bad character `\\x' + bc + '`')

    if not parsed:
        raise DonatelloConfigurationError(
            'received empty set of valid byte codes')

    return bytearray(parsed)


def _parse_max_factors(max_factors):
    """Parse the -m/--max-factors argument."""
    try:
        ret = int(max_factors)
        if ret < 2:
            raise ValueError
    except ValueError:
        raise DonatelloConfigurationError(
            '-m/--max-factors must be a positive integer >= 2')

    return ret


def _parse_ops(ops):
    """Parse the -o/--ops argument."""
    ret = tuple(ops.split(','))
    for op in ret:
        if op not in IMPLEMENTED_OPS:
            raise DonatelloConfigurationError(
                'invalid specified operation `' + op + '`')

    return ret


def _parse_target_hex(target):
    """Parse the target argument as a hex value."""
    try:
        if not target.startswith('0x'):
            print_w('`target` does not start with `0x` but is being '
                    'interpreted as a hex value')
        target_as_int = int(target, base=16)
    except ValueError:
        raise DonatelloConfigurationError(
            'expected hex value for `target` but got ' + target)

    if target_as_int.bit_length() > 32:
        raise DonatelloConfigurationError(
            'a maximum integer size of 32 bits is currently supported')

    return target_as_int


def main(args=None):
    """Main entry point for `donatello`'s command-line interface.

    Args:
        args (List[str]): Custom arguments if you wish to override sys.argv.

    Returns:
        int: The exit code of the program.

    """
    try:
        init_colorama()
        opts = get_parsed_args(args)

        if opts.bad_chars is not None:
            bad_chars = _parse_bytes(opts.bad_chars, check_dups=True)
        else:
            bad_chars = b''
        bad_chars_as_ints = tuple(int(bc) for bc in bad_chars)

        if opts.max_factors is not None:
            max_factors = _parse_max_factors(opts.max_factors)
        else:
            max_factors = 2

        if opts.ops is not None:
            ops = _parse_ops(opts.ops)
        else:
            ops = IMPLEMENTED_OPS

        if opts.command not in ('factor', 'encode',):
            raise DonatelloConfigurationError(
                'must specify either `factor` or `encode`; `' + opts.command +
                '` is invalid')

        if opts.target == '-':
            # TODO: https://docs.python.org/3/library/fileinput.html
            pass
        else:
            target = opts.target

        if opts.command == 'factor':
            value = _parse_target_hex(target)
            print_i('Attempting to factor target value ', format_dword(value))

            for num_factors in range(2, max_factors+1):
                factors = factor_by_byte(
                    value, bad_chars_as_ints, usable_ops=ops,
                    num_factors=num_factors)
                if factors is not None:
                    print_i('Found factorization!')
                    res = ['    0x00000000']
                    for f in factors:
                        res.append('{0: <3}'.format(f.operator) + ' ' +
                                   format_dword(f.operand))
                    print('\n'.join(res))
                    break
            else:
                print_e('Unable to find any factors')
        elif opts.command == 'encode':
            payload = _parse_bytes(target)
            print_i('Attempting to encode payload...')
            asm = encode_x86_32(payload, bad_chars, max_factors=max_factors)
            print_i('Successfully encoded payload!')
            print(asm)

        return 0
    except (DonatelloCannotEncodeError, DonatelloNoPossibleNopsError) as e:
        print_e('Failed to factor/encode the specified target: ', e)
        return 1
    except DonatelloConfigurationError as e:
        print_e('Configuration error: ', e)
        return 1
    except DonatelloNoPresentBadCharactersError:
        print_e('No bad characters present in the specified payload; ',
                'use the -f/--force flag to bypass this check')
        return 1
    except DonatelloError as e:
        print_e('This should not be reached! See below for error.')
        print_e(e)
        return 1
    except Exception as e:
        print_e('Received unexpected exception; re-raising it.')
        raise e
