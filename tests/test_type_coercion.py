import pytest

from int3 import Compiler, Int3InsufficientWidthError, Int3ProgramDefinitionError


def test_int_type_can_represent_value():
    cc = Compiler.from_host()

    for value in [0, 0x10, 0xFF]:
        assert cc.types.u8.can_represent_value(value)

    for value in [-0xFF, -1, 0xFF + 1]:
        assert not cc.types.u8.can_represent_value(value)

    for value in [-128, 0, 127]:
        assert cc.types.i8.can_represent_value(value)

    for value in [-129, 128]:
        assert not cc.types.i8.can_represent_value(value)


def test_int_type_can_represent_type():
    cc = Compiler.from_host()

    assert cc.types.u16.can_represent_type(cc.types.u8)
    assert not cc.types.u16.can_represent_type(cc.types.i8)
    assert not cc.types.u16.can_represent_type(cc.types.i32)
    assert cc.types.i64.can_represent_type(cc.types.u32)


def test_int_constant_bounds_checks():
    cc = Compiler.from_host()

    with pytest.raises(Int3InsufficientWidthError):
        cc.u8(0xFF + 1)

    with pytest.raises(Int3InsufficientWidthError):
        cc.u32(-1)

    cc.i32(0x7FFFFFFF)
    with pytest.raises(Int3InsufficientWidthError):
        cc.i32(0x7FFFFFFF + 1)

    cc.i32(-0x80000000)
    with pytest.raises(Int3InsufficientWidthError):
        cc.i32(-0x80000000 - 1)


def test_coerce_raw_int_to_type():
    cc = Compiler.from_host()

    var = cc.coerce_to_type(value=0xDEAD, type=cc.types.u32)
    assert var.type == cc.types.u32
    assert not var.type.is_signed
    assert var.value == 0xDEAD

    with pytest.raises(Int3InsufficientWidthError):
        cc.coerce_to_type(value=-1, type=cc.types.u8)


def test_coerce_raw_bytes_into_int_type():
    cc = Compiler.from_host()

    with cc.def_func.main():
        int_value = cc.coerce_to_type(value=b"xxx", type=cc.types.unat)
        assert int_value.type == cc.types.unat


def test_coerce_pointer_to_narrower_int_type():
    cc = Compiler.from_host()

    with cc.def_func.main():
        bytes_ptr = cc.b(b"test")

        with pytest.raises(Int3ProgramDefinitionError):
            cc.coerce_to_type(value=bytes_ptr, type=cc.types.i16)
