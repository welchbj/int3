# Tests for some corner cases in semantic emission. We usue x86_64 as the
# architecture under test, but the intent here is for architecture-agnostic
# tests that challenge the SemanticEmitter's logic.

import random

import pytest

from int3.context import Context
from int3.emission import Linuxx86_64Emitter
from int3.errors import (
    Int3ArgumentError,
    Int3CorruptedStackScopeError,
    Int3LockedRegisterError,
)


def test_duplicate_registers_in_lock():
    ctx = Context.from_host()
    emitter = Linuxx86_64Emitter(ctx=ctx)

    with pytest.raises(Int3ArgumentError):
        with emitter.locked("rax", "rax"):
            pass

    with pytest.raises(Int3ArgumentError):
        with emitter.locked("rax", "rbx", "rcx", "rdx", "rbx"):
            pass

    assert len(emitter.locked_gp_registers) == 0


def test_duplicated_register_locks_in_nested_contexts():
    ctx = Context.from_host()
    emitter = Linuxx86_64Emitter(ctx=ctx)

    with emitter.locked("r12"):
        assert len(emitter.locked_gp_registers) == 1
        assert "r12" in emitter.locked_gp_registers

        with emitter.locked("r11"):
            assert len(emitter.locked_gp_registers) == 2
            assert "r11" in emitter.locked_gp_registers

        with pytest.raises(Int3LockedRegisterError):
            with emitter.locked("r12"):
                pass

        assert len(emitter.locked_gp_registers) == 1
        assert "r12" in emitter.locked_gp_registers


def test_forced_gp_register_selection():
    ctx = Context.from_host()
    emitter = Linuxx86_64Emitter(ctx=ctx)

    gp_regs = emitter.arch.gp_regs
    free_reg = random.choice(gp_regs)
    all_but_one_gp_reg = set(gp_regs) - {free_reg}

    with emitter.locked(*all_but_one_gp_reg):
        assert emitter.free_gp_registers == (free_reg,)
        assert emitter.pop() == free_reg

        with emitter.locked(free_reg):
            with pytest.raises(Int3LockedRegisterError):
                emitter.pop()


def test_short_circuit_xor():
    ctx = Context.from_host()
    emitter = Linuxx86_64Emitter(ctx=ctx)

    emitter.mov("rax", 0)
    assert str(emitter).strip() == "xor rax, rax"


def test_requires_factoring_force_sub():
    # >>> add rax, rbx
    # b"\x48\x01\xd8"
    # >>> sub rax, rbx
    # b"\x48\x29\xd8"
    # >>> xor rax, rbx
    # b"\x48\x31\xd8"
    ctx = Context.from_host(bad_bytes=b"\x01\x31\x41")
    emitter = Linuxx86_64Emitter(ctx=ctx)

    emitter.mov("rax", 0x41414141)
    assert str(emitter).strip() == "xor rax, rax"


def test_requires_factoring_force_xor():
    # TODO
    pass


def test_requires_factoring_force_add():
    # TODO
    pass


# def test_requires_factoring_force_neg():
#     # TODO
#     pass


def test_stack_scope_push_pop():
    ctx = Context.from_host()
    emitter = Linuxx86_64Emitter(ctx=ctx)

    with emitter.stack_scope() as stack_scope_one:
        assert emitter.current_stack_scope is stack_scope_one

        emitter.push(0xDEAD)
        assert stack_scope_one.stack_change == -8

        with emitter.stack_scope() as stack_scope_two:
            assert stack_scope_two is not stack_scope_one
            assert emitter.current_stack_scope is stack_scope_two

            for i in range(0x10):
                emitter.push(0xBEEF)
                assert stack_scope_two.stack_change == (i + 1) * -8

        emitter.pop("rbx")
        assert stack_scope_one.stack_change == 0

    assert emitter.current_stack_scope.stack_change == 0


def test_stack_scope_ret():
    ctx = Context.from_host()
    emitter = Linuxx86_64Emitter(ctx=ctx)

    with emitter.stack_scope(ret=True):
        pass

    assert str(emitter).strip() == "ret"
    assert emitter.current_stack_scope.stack_change == 8


def test_stack_scope_literals():
    ctx = Context.from_host()
    emitter = Linuxx86_64Emitter(ctx=ctx)

    with emitter.stack_scope() as stack_scope:
        emitter.add("rsp", 0xDEAD)
        assert stack_scope.stack_change == 0xDEAD

    assert stack_scope.stack_change == 0


def test_stack_scope_corrupted():
    ctx = Context.from_host()
    emitter = Linuxx86_64Emitter(ctx=ctx)

    with pytest.raises(Int3CorruptedStackScopeError):
        with emitter.stack_scope() as stack_scope:
            emitter.mov("rsp", 0xCAFE)
            assert stack_scope.is_corrupted
