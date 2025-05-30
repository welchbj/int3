from int3 import Compiler, HlirIntConstant


def test_int_constant_factories_u8():
    cc = Compiler.from_host()

    for valid_value in [0, 0x10, 0xFF]:
        assert cc.u8().is_representable(valid_value)

    for invalid_value in [-0xFF, -1, 0xFF + 1]:
        assert not cc.u8().is_representable(invalid_value)


def test_int_constant_factories_i8():
    cc = Compiler.from_host()

    for valid_value in [-128, 0, 127]:
        assert cc.i8().is_representable(valid_value)

    for invalid_value in [-129, 128]:
        assert not cc.i8().is_representable(invalid_value)
