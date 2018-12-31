"""A few 32-bit operation factorizations."""

from collections import (
    namedtuple)
from functools import (
    lru_cache)
from tt import (
    BooleanExpression,
    to_cnf)

from .constants_x86_32 import (
    IMPLEMENTED_OPS)

Factor = namedtuple('Factor', ['operator', 'operand'])


def _cnfify(exprs):
    """Convert a sequence of expressions to their CNF form."""
    return ['(' + str(to_cnf(expr)) + ')' for expr in exprs]


@lru_cache(maxsize=None)
def factor_dword_bitwise(target, bad_chars, ops=IMPLEMENTED_OPS,
                         num_factors=2):
    """TODO.

    Args:
        TODO
        target (int): TODO

    Returns:
        TODO

    """
    # TODO: gen permutations
    # TODO
    pass


@lru_cache(maxsize=None)
def factor_byte_bitwise(target, bad_chars, op='and', num_factors=2):
    """TODO.

    Args:
        TODO
        bad_chars (Tuple[int]): Bad characters that cannot be used,
            represented as a tuple of integers so that it can be hashed
            by the caching decorator.

    Returns:
        List[int]: TODO

    """
    # build our factor clauses
    factor_clauses = []
    for i in range(8):
        # b0_f0 -> bit 0 of factor 0, etc.
        bit_vars = ['b{}_f{}'.format(i, j) for j in range(num_factors)]
        clause = '(' + ' {} '.format(op).join(bit_vars) + ')'

        if not (target & (1 << i)):
            clause = '~' + clause

        factor_clauses.append(clause)

    # build bad character constraint clauses
    char_constraint_clauses = []
    for bad_char in bad_chars:
        for j in range(num_factors):
            bit_vars = ['b{}_f{}'.format(i, j) for i in range(8)]
            clause = [
                var if (bad_char & (1 << i)) else '~' + var for
                i, var in enumerate(bit_vars)]
            char_constraint_clauses.append(
                '~(' + ' and '.join(clause) + ')')

    # build the expression we aim to satisfy
    expr = ''
    expr += ' and '.join(_cnfify(factor_clauses))
    expr += ' and '
    expr += ' and '.join(_cnfify(char_constraint_clauses))

    # try solving the sat problem
    b = BooleanExpression(expr)
    sat_sol = b.sat_one()
    if sat_sol is None:
        return None

    # we have a solution, now we need to turn it into the factors
    factors = []
    for j in range(num_factors):
        factor = 0
        for i in range(8):
            bit = getattr(sat_sol, 'b{}_f{}'.format(i, j))
            factor |= (bit << i)
        factors.append(factor)
    return factors


@lru_cache(maxsize=None)
def factor_by_byte(target, bad_chars, op='and', num_factors=2):
    """TODO.

    Returns:
        List[Factor]: TODO

    """
    # TODO: check if num_factors is >= 2
    msb_factors = \
        factor_byte_bitwise(target >> 24, bad_chars, op, num_factors)
    if msb_factors is None:
        return None

    second_msb_factors = \
        factor_byte_bitwise((target >> 16) & 0xff, bad_chars, op, num_factors)
    if second_msb_factors is None:
        return None

    second_lsb_factors = \
        factor_byte_bitwise((target >> 8) & 0xff, bad_chars, op, num_factors)
    if second_lsb_factors is None:
        return None

    lsb_factors = \
        factor_byte_bitwise(target & 0xff, bad_chars, op, num_factors)
    if lsb_factors is None:
        return None

    num_factors = len(msb_factors)
    factors = []
    for i in range(num_factors):
        operand = 0
        operand |= msb_factors[i] << 24
        operand |= second_msb_factors[i] << 16
        operand |= second_lsb_factors[i] << 8
        operand |= lsb_factors[i]
        factors.append(Factor(op, operand))
    return factors


@lru_cache(maxsize=None)
def factor_by_dword(target, bad_chars, ops=IMPLEMENTED_OPS, num_factors=2):
    """TODO."""
    # TODO
