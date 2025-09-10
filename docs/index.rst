====
int3
====

Welcome to the documentation site for the int3 framework.

-----

.. warning::

    ``int3`` is heavily tested and somewhat usable, but is still pre-1.0/stable software. This means there are several features yet to be implemented as well as **no guarantees** of avoiding breaking API changes prior to version 1.0.


Synopsis
--------

``int3`` is a Python toolkit for writing low-level, position-independent code featuring the following...

A high-level command-line interface for common assembly tasks:

.. code-block:: bash

    echo -n "int3" | int3 assemble -a x86_64 | int3 format
    b"\xcc"

A full-featured Python framework interface for writing your own position-independent programs:

.. literalinclude:: ../examples/linux/hello_world.py
    :language: python

Support for executing them:

.. code-block:: bash

    python3 examples/linux/hello_world.py | int3 execute
    Hello, world


Installation
------------

int3 is tested on the latest three major versions of CPython. You can get the latest release from PyPI with:

.. code-block:: bash

    pip install int3


Features
--------

TODO


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
