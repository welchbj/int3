========
Coverage
========

Architectures and Platforms
===========================

``int3`` aims to provide the building blocks for extending compiler coverage to a variety of architectures and platforms. Support is currently limited to Linux compilation for ``x86_64``, ``x86``, and ``Mips``.

It will be feasible, with some work, to add support for other operating systems and many more architectures. The realm of possibilities is largely restricted to triples supported by LLVM and architectures supported by Capstone and Keystone.

-----

Current Limitations
===================

There are several unimplemented features that are not inherently unsupportable. The only real obstacle preventing the addition of these items is time.

Perfect bad byte removal
~~~~~~~~~~~~~~~~~~~~~~~~

Removing bad bytes from compiled machine code employs a "best effort" approach across a variety of passes. While this performed somewhat intelligently (using techniques like splitting immediate construction across multiple instructions), this will always be a non-exhaustive approach.

More passes can be added in the future to work around some current limitations. Specific troublesome program patterns are welcome as `new issues <https://github.com/welchbj/int3/issues>`_.

Operating on machine code also introduces more architecture-specific concerns, which can make development of these features slower than higher-level features built on top of LLVM IR.

Control flow mutation
~~~~~~~~~~~~~~~~~~~~~

Code mutation passes often emit replacement gadgets that are not the same length as the code they are replacing. While these changes are localized to functions, these mutations can break relative offsets within that function's branches or jumps. More work is required to workaround these situations.

Value Types
~~~~~~~~~~~

Only integer values and the specialized bytes pointer type are currently implemented. A natural next category of types to support is LLVM's floating point.

Function "forward declarations"
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``int3`` compiler's function resolution is not lazy and expects to be able to resolve a called function at the time of its call in the program declaration. This requires developers to avoid "forward declaring" their functions and therefore must define them before trying to call them. This is too restrictive and should be removed in a future version.

Recursive Function Calling
~~~~~~~~~~~~~~~~~~~~~~~~~~

No attempt has been made to support recursive function calling. If this works, it is only by coincidence.
