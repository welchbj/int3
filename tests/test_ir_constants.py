from int3 import IrIntConstant


def test_int_constant_factories_u8():
    for valid_value in [0, 0x10, 0xFF]:
        assert IrIntConstant.u8().is_representable(valid_value)

    for invalid_value in [-0xFF, -1, 0xFF + 1]:
        assert not IrIntConstant.u8().is_representable(invalid_value)


def test_int_constant_factories_i8():
    for valid_value in [-128, 0, 127]:
        assert IrIntConstant.i8().is_representable(valid_value)

    for invalid_value in [-129, 128]:
        assert not IrIntConstant.i8().is_representable(invalid_value)
