"""Command-line interface for `donatello`."""

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
from .errors import (
    DonatelloCannotEncodeError,
    DonatelloConfigurationError,
    DonatelloError,
    DonatelloNoPossibleNopsError,
    DonatelloNoPresentBadCharactersError)
from .io import (
    print_e,
    print_i,
    print_w)


def get_parsed_args(args=None):
    """Get the parsed command-line arguments."""
    parser = ArgumentParser(
        prog='donatello',
        usage='dontallo [OPTIONS] <factor|encode> target',
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

    parser.add_argument(
        '-b', '--bad-chars',
        action='store',
        metavar='',
        help='bad characters in the format `\\x00\\x01` that cannot be\n'
             'present in the factored/encoded result')

    parser.add_argument(
        '-m', '--max-factors',
        action='store',
        metavar='',
        help='the maximum number of factors used to generate each portion of\n'
             'the target value or payload')

    parser.add_argument(
        '-o', '--ops',
        action='store',
        metavar='',
        help='comma-delimited list of operations permitted to be used in the\n'
             'encoding (`or`, `and`, `xor`, etc.); defaults to all\n'
             'implemented x86 arithmetic operations not violating the bad\n'
             'character set')

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

    # TODO: read this from stdin, too (https://docs.python.org/3/library/fileinput.html)
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


def _parse_bad_chars(bad_chars):
    """Parse the -b/--bad-characters argument."""
    _cache = set()
    parsed = []
    for bc in bad_chars.split('\\x')[1:]:
        try:
            parsed_bc = int(bc, base=16)
            if parsed_bc < 0 or parsed_bc > 255:
                raise ValueError
            elif parsed_bc in _cache:
                print_w('`\\x', bc, '` is present multiple times in your '
                        '-b/--bad-chars argument')
                continue
            parsed.append(parsed_bc)
            _cache.add(parsed_bc)
        except ValueError:
            raise DonatelloConfigurationError(
                'invalid bad character `\\x' + bc + '`')

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
    ret = ops.split(',')
    for op in ret:
        if op not in IMPLEMENTED_OPS:
            raise DonatelloConfigurationError(
                'invalid specified operation `' + op + '`')

    return ret


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
            bad_chars = _parse_bad_chars(opts.bad_chars)
        else:
            bad_chars = b''

        if opts.max_factors is not None:
            max_factors = _parse_max_factors(opts.max_factors)
        else:
            max_factors = 2

        if opts.ops is not None:
            ops = _parse_ops(opts.ops)
        else:
            ops = IMPLEMENTED_OPS

        if opts.command not in ('factor', 'encode',):
            # TODO
            pass
        elif opts.command == 'factor':
            # TODO
            pass
        elif opts.command == 'encode':
            # TODO
            pass

        if opts.target == '-':
            # TODO
            pass
        else:
            # TODO
            pass
    except DonatelloConfigurationError as e:
        print_e('Configuration error: ', e)
        return 1
    except DonatelloError as e:
        print_e('This should not be reached! See below for error.')
        print_e(e)
        return 1
    except Exception as e:
        print_e('Received unexpected exception; re-raising it.')
        raise e
