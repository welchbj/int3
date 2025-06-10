import pytest

from int3 import Compiler
from int3.errors import (
    Int3CompilationError,
    Int3ContextError,
    Int3ProgramDefinitionError,
)


def test_no_active_function():
    cc = Compiler.from_host()

    with pytest.raises(Int3ContextError):
        var = cc.i(0xBEEF)
        cc.add(var, 2)


def test_not_defining_an_entrypoint():
    cc = Compiler.from_host()

    with cc.def_func.not_the_entrypoint():
        ...

    with pytest.raises(Int3CompilationError):
        cc.compile()


def test_non_void_entrypoint():
    cc = Compiler.from_host()

    with cc.def_func.main(int):
        cc.ret(0xCAFE)

    with pytest.raises(Int3CompilationError):
        cc.compile()


def test_invalid_byte_declarations():
    cc = Compiler.from_host()

    with cc.def_func.main():
        with pytest.raises(Int3ProgramDefinitionError):
            cc.b(value=b"")

        with pytest.raises(Int3ProgramDefinitionError):
            cc.b(value=b"x", len_=0)

        with pytest.raises(Int3ProgramDefinitionError):
            cc.b(value=b"x" * 0x10, len_=0x8)


def test_func_with_byte_pointer_argument():
    # TODO
    assert False
