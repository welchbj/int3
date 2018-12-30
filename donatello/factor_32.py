"""A few 32-bit operation factorizations."""

from functools import (
    lru_cache)
from tt import (
    BooleanExpression,
    to_cnf)


def _cnfify(exprs):
    """Convert a sequence of expressions to their CNF form."""
    return ['(' + str(to_cnf(expr)) + ')' for expr in exprs]


@lru_cache(maxsize=None)
def factor_byte_bitwise(target, bad_chars, op='and', max_factors=2):
    """TODO.

    Args:
        TODO
        bad_chars (Tuple[int]): Bad characters that cannot be used,
            represented as a tuple of integers so that it can be hashed
            by the caching decorator.

    Returns:
        List[int]: TODO

    """
    for num_factors in range(2, max_factors + 1):
        # build our factor clauses
        factor_clauses = []
        for i in range(8):
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
            continue

        # we have a solution, now we need to turn it into the factors
        factors = []
        for j in range(num_factors):
            factor = 0
            for i in range(8):
                bit = getattr(sat_sol, 'b{}_f{}'.format(i, j))
                factor |= (bit << i)
            factors.append(factor)
        return factors

    return None


@lru_cache(maxsize=None)
def factor_bitwise(target, bad_chars, op='and', max_factors=2):
    """TODO."""
    # TODO: check if max_factors is >= 2
    msb_factors = \
        factor_byte_bitwise(target >> 24, bad_chars, op, max_factors)
    if msb_factors is None:
        return None

    second_msb_factors = \
        factor_byte_bitwise((target >> 16) & 0xff, bad_chars, op, max_factors)
    if second_msb_factors is None:
        return None

    second_lsb_factors = \
        factor_byte_bitwise((target >> 8) & 0xff, bad_chars, op, max_factors)
    if second_lsb_factors is None:
        return None

    lsb_factors = \
        factor_byte_bitwise(target & 0xff, bad_chars, op, max_factors)
    if lsb_factors is None:
        return None

    num_factors = len(msb_factors)
    factors = []
    for i in range(num_factors):
        factor = 0
        factor |= msb_factors[i] << 24
        factor |= second_msb_factors[i] << 16
        factor |= second_lsb_factors[i] << 8
        factor |= lsb_factors[i]
        factors.append(factor)
    return factors


def factor_or(target, bad_chars, max_factors=2):
    """Compute factors for 32-bit or."""
    return factor_bitwise(target, bad_chars, op='or', max_factors=max_factors)


def factor_and(target, bad_chars, max_factors=2):
    """Compute factors for 32-bit and."""
    return factor_bitwise(target, bad_chars, op='and', max_factors=max_factors)


def factor_xor(target, bad_chars, max_factors=2):
    """Compute factors for 32-bit xor."""
    return factor_bitwise(target, bad_chars, op='xor', max_factors=max_factors)
