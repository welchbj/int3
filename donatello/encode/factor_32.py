"""A few 32-bit operation factorizations."""

from collections import (
    namedtuple)
from functools import (
    lru_cache)
from itertools import (
    chain,
    product)
from tt import (
    BooleanExpression,
    to_cnf)

from .constants_x86_32 import (
    IMPLEMENTED_OPS,
    NUM_BITS_IN_BYTE)
from .errors import (
    DonatelloConfigurationError)
from .io import (
    format_dword)

Factor = namedtuple('Factor', ['operator', 'operand'])


def _cnfify(exprs):
    """Convert a sequence of expressions to their CNF form."""
    return ['(' + str(to_cnf(expr)) + ')' for expr in exprs]


@lru_cache(maxsize=None)
def _factor_bitwise(target, num_bits, bad_chars, ops, start_value):
    """The engine behind everything novel in this project.

    Args:
        target (int): TODO
        bad_chars (Tuple[int]): TODO
        num_bits (int): TODO
        ops (List[str]): TODO
        num_factors (int): TODO
        start_value (int): TODO

    Returns:
        List[int]: TODO

    """
    num_factors = len(ops)

    # build factor clauses
    factor_clauses = []
    for i in range(num_bits):
        # b0_f0 -> bit 0 of factor 0, etc.
        bit_vars = iter('b{}_f{}'.format(i, j) for j in range(num_factors))

        clause = str(int(bool(start_value & (1 << i))))
        for op, bit_var in zip(ops, bit_vars):
            clause = '({} {} {})'.format(clause, op, bit_var)

        if not (target & (1 << i)):
            clause = '~' + clause

        factor_clauses.append(clause)

    # build bad character constraint clauses
    char_constraint_clauses = []
    for bad_char, j in product(bad_chars, range(num_factors)):
        bit_vars = iter('b{}_f{}'.format(i, j) for i in range(num_bits))
        clause = [
            var if (bad_char & (1 << i)) else '~' + var for
            i, var in enumerate(bit_vars)]
        char_constraint_clauses.append(
            '~(' + ' and '.join(clause) + ')')

    # build the expression we aim to satisfy
    cnf_clauses = chain(
        _cnfify(factor_clauses),
        _cnfify(char_constraint_clauses))
    expr = ' and '.join(cnf_clauses)

    # try solving the sat problem
    b = BooleanExpression(expr)
    sat_sol = b.sat_one()
    if sat_sol is None:
        return None

    # we have a solution, now we need to turn it into the factors
    factors = []
    for j in range(num_factors):
        factor = 0
        for i in range(num_bits):
            bit = getattr(sat_sol, 'b{}_f{}'.format(i, j))
            factor |= (bit << i)
        factors.append(factor)
    return factors


@lru_cache(maxsize=None)
def factor_by_byte(target, bad_chars, usable_ops=IMPLEMENTED_OPS,
                   num_factors=2, start_value=0):
    """TODO.

    Args:
        TODO

    Returns:
        List[Factor]: TODO

    Raises:
        DonatelloConfigurationError: If `num_factors` is less than 2.

    """
    if num_factors < 2:
        raise DonatelloConfigurationError('`num_factors` must be >= 2')

    for op_perm in product(usable_ops, repeat=num_factors):
        if start_value == 0 and op_perm[0] == 'and':
            continue

        msb_factors = _factor_bitwise(
            (target >> 24) & 0xff, NUM_BITS_IN_BYTE, bad_chars, op_perm,
            (start_value >> 24) & 0xff)
        if msb_factors is None:
            continue

        second_msb_factors = _factor_bitwise(
            (target >> 16) & 0xff, NUM_BITS_IN_BYTE, bad_chars, op_perm,
            (start_value >> 16) & 0xff)
        if second_msb_factors is None:
            continue

        second_lsb_factors = _factor_bitwise(
            (target >> 8) & 0xff, NUM_BITS_IN_BYTE, bad_chars, op_perm,
            (start_value >> 8) & 0xff)
        if second_lsb_factors is None:
            continue

        lsb_factors = _factor_bitwise(
            target & 0xff, NUM_BITS_IN_BYTE, bad_chars, op_perm,
            start_value & 0xff)
        if lsb_factors is None:
            continue

        num_factors = len(msb_factors)
        factors = []
        for i in range(num_factors):
            operand = 0
            operand |= msb_factors[i] << 24
            operand |= second_msb_factors[i] << 16
            operand |= second_lsb_factors[i] << 8
            operand |= lsb_factors[i]
            factors.append(Factor(op_perm[i], operand))
        return factors

    return None
