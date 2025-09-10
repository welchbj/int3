==========
User Guide
==========

Defining functions and programs
===============================

Compiler interface
------------------

The ``int3`` library provides a high-level Python interface for generating position-independent machine code. The most natural way to obtain a compiler instance is using one of the factory methods on the :py:class:`~int3.compilation.compiler.Compiler` class itself:

.. doctest::

    >>> from int3 import Compiler
    >>> cc = Compiler.from_str("linux/x86_64")
    >>> type(cc)
    'Linux'

Load addresses
--------------

While the ultimate goal of an ``int3`` program is to be truly position-independent, that's not always possible. We cannot overcome every bad byte constraint for every program. This is especially true for our program counter derivation stubs, which inherently rely on specific instructions for each supported architecture.

We can avoid some of these issues if we know what address our program will be loaded at. This greatly simplifies the program's initialization stub and its symbol table construction, which in turn means it will likely be easier to avoid your bad byte constraints, but it also means our program is no longer position-independent.

A static load address can be specified with:

.. doctest::

    >>> assert False

Bad bytes
---------

When we initialize our compiler, we can inform it of bad bytes we want to avoid in our generated machine code. For example:

.. doctest::

    >>> cc = Compiler.from_str("linux/x86_64", bad_bytes=b"\x00")
    >>> with cc.def_func.main():
    ...     # This might normally generate null bytes
    ...     value = cc.i32(0x12345678)
    ...     cc.ret(value)
    >>> machine_code = cc.compile()
    >>> b'\x00' in machine_code
    False

Bad bytes are removed after our compiler's LLVM IR has been translated to its initial series of per-function machine code segments. We then apply a series of mutation passes to lift and transform these machine instructions to do things like replacing dirty instructions with their semantic equivalents and breaking apart dirty immediate values into multiple operations with clean immediate values.

Defining functions
------------------

The main unit of execution within an ``int3`` program is a function. Functions are defined using the :py:attr:`~int3.Compiler.def_func` attribute as a context manager, with the enclosed scope of that context manager defining the function's body.

The simplest function definition creates a function with no arguments and a void return type:

.. doctest::

    >>> from int3 import Compiler
    >>> cc = Compiler.from_host()
    >>> with cc.def_func.my_function():
    ...     pass
    >>> cc.func.my_function.return_type == cc.types.void
    True

Arguments can be specified using Python type hints or :py:mod:`int3` types, and we can then access those arguments from within the function definition:

.. doctest::

    >>> with cc.def_func.add_numbers(int, int):
    ...     a = cc.func.add_numbers.args[0]
    ...     b = cc.func.add_numbers.args[1]
    ...     result = cc.add(a, b)
    ...     cc.ret(result)
    >>> cc.func.add_numbers.return_type == cc.types.inat
    True

Note in the above example that the Python ``int`` type was promoted to our compiler's native width. We can enforce a specific return type with:

.. doctest::

    >>> with cc.def_func.get_value(return_type=cc.types.i32):
    ...     cc.ret(cc.i32(42))
    >>> cc.func.get_value.return_type == cc.types.i32
    True

Calling functions
-----------------

.. doctest::

    >>> assert False
    >>> with cc.def_func.helper():
    ...     cc.ret(cc.i(42))
    >>> with cc.def_func.main():
    ...     result = cc.call.helper()
    ...     cc.ret(result)


Program entrypoint
------------------

TODO

Conditional control flow
------------------------

``int3`` supports conditional execution using :py:meth:`~int3.Compiler.if_else` blocks. Conditions are created using comparison operations that implicitly produce :py:class:`~int3.Predicate` instances:

.. doctest::

    >>> from int3 import Compiler
    >>> cc = Compiler.from_host()
    >>> with cc.def_func.check_value():
    ...     x = cc.i(1)
    ...     with cc.if_else(x > 2) as (if_, else_):
    ...         with if_:
    ...             result = cc.i(1)
    ...         with else_:
    ...             result = cc.i(0)
    ...     cc.ret(result)

The astute reader will have noticed that the :py:class:`~int3.IntValue` and :py:class:`~int3.IntConstant` instances have overloaded most Python dunder methods for basic arithmetic operations.

-----

Linux-specific interface
========================

TODO

-----

Anatomy of an ``int3``-generated program
========================================

Functions
---------

Each function in an ``int3`` program becomes a separate code segment in the generated program. Functions are compiled to use the target platform's calling convention and can call each other. Functions are treated as independent units of execution, whose main interface TODO. Consequently, each function is "cleaned" of bad bytes in isolation during the compilation process before being stitched back together.

Entry Stub
----------

When you compile an ``int3`` program using :py:meth:`~int3.Compiler.compile`, the generated machine code includes an entry stub that handles program initialization and calls your entrypoint function. This initialization involves

* Running a program counter derivation stub so we can figure out where we're running in memory
* Setting up offsets in the per-program symbol table
* Invoke the entrypoint function of the program

The program symbol table is passed as an implicit argument to each function call, with offsets into this symbol data being computed at compile time to enable simple runtime resolution of required addresses.
