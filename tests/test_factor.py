import pytest

from int3.context import Context
from int3.errors import Int3ArgumentError, Int3SatError
from int3.factor import FactorClause, FactorOperation, FactorResult, compute_factor


def test_target_with_invalid_width():
    with pytest.raises(Int3ArgumentError):
        compute_factor(
            target=0x12345678,
            ctx=Context.from_host(),
            width=8,
        )


def test_width():
    factor_result = compute_factor(
        target=0x41,
        ctx=Context.from_host(bad_bytes=b"\x41"),
        width=8,
    )

    assert eval(str(factor_result)) & 0xFF == 0x41


def test_unsat_constraints():
    with pytest.raises(Int3SatError):
        compute_factor(
            target=0xDEAD,
            ctx=Context.from_host(bad_bytes=bytes(range(0xFF))),
            max_depth=1,
        )


def test_allowed_and_forbidden_ops():
    factor_result = compute_factor(
        target=0x41414141,
        ctx=Context.from_host(bad_bytes=b"\x41"),
        width=0x20,
        allowed_ops=[FactorOperation.Sub],
    )

    assert eval(str(factor_result)) & 0xFFFFFFFF == 0x41414141

    assert factor_result.clauses[0].operation == FactorOperation.Init
    for clause in factor_result.clauses[1:]:
        assert clause.operation == FactorOperation.Sub


def test_specified_start_value():
    factor_result = compute_factor(
        target=0x41414141,
        start=0x40404040,
        ctx=Context.from_host(bad_bytes=b"\x41\x42"),
        width=0x20,
        allowed_ops=[FactorOperation.Xor],
    )

    assert eval(str(factor_result)) & 0xFFFFFFFF == 0x41414141

    first_clause = factor_result.clauses[0]
    assert first_clause.operation == FactorOperation.Init
    assert first_clause.operand == 0x40404040


def test_start_value_has_bad_bytes():
    with pytest.raises(Int3ArgumentError):
        compute_factor(
            target=0x41414141,
            start=0x12005678,
            width=0x20,
            ctx=Context.from_host(bad_bytes=b"\x00"),
        )


def test_invalid_max_depth():
    with pytest.raises(Int3ArgumentError):
        compute_factor(target=0x12345678, ctx=Context.from_host(), max_depth=-1)

    with pytest.raises(Int3ArgumentError):
        compute_factor(target=0x12345678, ctx=Context.from_host(), max_depth=0)


def test_invalid_forbidden_ops():
    with pytest.raises(Int3ArgumentError):
        compute_factor(
            target=0x12345678,
            ctx=Context.from_host(),
            forbidden_ops=[FactorOperation.Init],
        )


def test_factor_result_to_str():
    factor_result = FactorResult(clauses=tuple())
    assert str(factor_result) == ""

    factor_result = FactorResult(clauses=(FactorClause(FactorOperation.Init, 0xCAFE),))
    assert str(factor_result) == "0xcafe"

    factor_result = FactorResult(
        clauses=(
            FactorClause(FactorOperation.Init, 0xCAFE),
            FactorClause(FactorOperation.Add, 0xDEAD),
            FactorClause(FactorOperation.Sub, 0xBEEF),
        )
    )
    assert str(factor_result) == "0xcafe + 0xdead - 0xbeef"

    factor_result = FactorResult(
        clauses=(
            FactorClause(FactorOperation.Init, 0xCAFE),
            FactorClause(FactorOperation.Add, 0xDEAD),
            FactorClause(FactorOperation.Neg, -1),
            FactorClause(FactorOperation.Sub, 0xBEEF),
        )
    )
    assert str(factor_result) == "~(0xcafe + 0xdead) - 0xbeef"

    factor_result = FactorResult(
        clauses=(
            FactorClause(FactorOperation.Init, 0xCAFE),
            FactorClause(FactorOperation.Add, 0xDEAD),
            FactorClause(FactorOperation.Neg, -1),
            FactorClause(FactorOperation.Neg, -1),
            FactorClause(FactorOperation.Sub, 0xBEEF),
            FactorClause(FactorOperation.Neg, -1),
        )
    )
    assert str(factor_result) == "~(~(~(0xcafe + 0xdead)) - 0xbeef)"
