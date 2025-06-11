import pytest

from int3 import Compiler, Int3CompilationError


def test_implicit_void_return_type():
    cc = Compiler.from_host()

    with cc.def_func.my_func():
        ...

    assert cc.func.my_func.return_type == cc.types.void


def test_int_argument_shorthand_conversion():
    cc = Compiler.from_host()

    with cc.def_func.my_func(int, int):
        cc.ret(12345)

    assert cc.func.my_func.return_type == cc.types.inat
    assert cc.func.my_func.arg_types[1:] == [cc.types.inat]


def test_bytes_argument_shorthand_conversion():
    cc = Compiler.from_host()

    with cc.def_func.my_func(None, bytes):
        ...

    assert cc.func.my_func.return_type == cc.types.void
    assert cc.func.my_func.arg_types[0] == cc.types.ptr


def test_invalid_function_dont_return_value_with_non_void_return_type():
    cc = Compiler.from_host()

    with pytest.raises(Int3CompilationError):
        with cc.def_func.my_func(return_type=int):
            ...


def test_invalid_function_return_value_with_void_return_type():
    cc = Compiler.from_host()

    with pytest.raises(Int3CompilationError):
        with cc.def_func.my_func(return_type=cc.types.void):
            cc.ret(123)
