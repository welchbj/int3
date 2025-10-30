====
int3
====

Welcome to the documentation site for the ``int3`` framework.

-----

.. warning::

    ``int3`` is heavily tested and somewhat usable, but is still pre-1.0/stable software. This means there are several features yet to be implemented as well as **no guarantees** of avoiding breaking API changes prior to version 1.0.


Synopsis
--------

``int3`` is a Python toolkit for writing low-level, position-independent code featuring the following...

A high-level command-line interface for common assembly tasks:

.. code-block:: bash

    $ echo -n "int3" | int3 assemble -a x86_64 | int3 format
    b"\xcc"

A Python interface for writing your own position-independent programs with automatic bad byte avoidance:

.. literalinclude:: ../examples/linux/hello_world.py
    :language: python

Support for disassembling them:

.. code-block:: bash

    $ python3 examples/linux/hello_world.py | int3 disassemble | tail -10
    0x0078: inc edx
    0x007a: inc edx
    0x007c: inc edx
    0x007e: inc edx
    0x0080: mov rax, rdi
    0x0083: syscall
    0x0085: mov rdi, rax
    0x0088: mov eax, 0x3c
    0x008d: syscall
    0x008f: ret

And executing them:

.. code-block:: bash

    $ python3 examples/linux/hello_world.py | int3 execute ; echo $?
    Hello, world
    13


Supported Platforms
-------------------

``int3`` has support for the following cross-compilation targets:

+----------+-------------+-------+------------+-------------------+
| Platform | Name        | Width | Endianness | Shorthand         |
+==========+=============+=======+============+===================+
| Linux    | ``x86``     | 32    | Little     | ``linux/x86``     |
+----------+-------------+-------+------------+-------------------+
| Linux    | ``x86_64``  | 64    | Little     | ``linux/x86_64``  |
+----------+-------------+-------+------------+-------------------+
| Linux    | ``mips``    | 32    | Big        | ``linux/mips``    |
+----------+-------------+-------+------------+-------------------+
| Linux    | ``arm``     | 32    | Little     | ``linux/arm``     |
+----------+-------------+-------+------------+-------------------+
| Linux    | ``aarch64`` | 64    | Little     | ``linux/aarch64`` |
+----------+-------------+-------+------------+-------------------+

Note that available bad byte removal techniques or position-independent program counter derivation techniques will vary by architecture and platform, which may affect the ability to cross-compile a given program to all supported compilation targets.


Installation
------------

``int3`` is tested on the latest major version of CPython. You can get the latest release from PyPI with:

.. code-block:: bash

    pip install int3


Features
--------

* Write position-independent assembly code in a higher-level Python interface
* Builtin support for cross-compiling to various architectures
* Mutate generated machine code to remove bad bytes
* Command-line interface for common formatting and exploratory reversing tasks


License & Usage
---------------

``int3`` is intended for educational use. ``int3``'s unique code is released under the `GNU LGPLv3 <https://choosealicense.com/licenses/lgpl-3.0>`_, as per the ``LICENSE.txt`` file in the root of this repository. Code belonging to other open source projects is licensed under the respective licenses of those projects.

.. toctree::
    :hidden:

    user_guide
    coverage
    development
    prior_art
    acknowledgements


Want to learn more?
-------------------

If you're just getting started and looking for tutorial-style documentation, head on over to the :doc:`User Guide </user_guide>`. If you would prefer a comprehensive view of this library's functionality, check out the API docs:

.. toctree::
    :maxdepth: 1
    :glob:

    api/*
