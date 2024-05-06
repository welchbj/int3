import pytest

from int3 import Int3IrMismatchedTypeError, IrIntConstant, IrIntType


def test_int_constant_factories_u8():
    for valid_value in [0, 0x10, 0xFF]:
        const = IrIntConstant.u8(valid_value)
        assert const.type_ == IrIntType.u8()

    for invalid_value in [-0xFF, -1, 0xFF + 1]:
        with pytest.raises(Int3IrMismatchedTypeError):
            IrIntConstant.u8(invalid_value)


def test_int_constant_factories_i8():
    for valid_value in [-128, 0, 127]:
        const = IrIntConstant.i8(valid_value)
        assert const.type_ == IrIntType.i8()

    for invalid_value in [-129, 128]:
        with pytest.raises(Int3IrMismatchedTypeError):
            IrIntConstant.i8(invalid_value)
