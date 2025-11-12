"""Simple tests for the CodeGeneration API.

These tests are not all encompassing. The CodeGeneration implementation is
heavily test by proxy through several other tests files, like program
compilation and the tests related to Choice implementation.

"""

import pytest

from int3 import CodeGenerator, Int3MissingEntityError, Triple


def test_codegen_use_of_invalid_register():
    triple = Triple.from_str("x86_64-linux")
    codegen = CodeGenerator(triple)

    with pytest.raises(Int3MissingEntityError):
        codegen.jump("not_a_reg")
