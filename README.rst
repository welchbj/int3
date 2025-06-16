Synopsis
--------

``int3`` is a Python toolkit for writing low-level, position-independent code featuring the following...

A high-level command-line interface for common assembly tasks:

.. code-block:: bash

    echo -n "int3" | int3 assemble | int3 format
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

``int3`` is intended for educational use. ``int3``'s unique code is released under the `GPLv2 license <https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html>`_, as per the ``LICENSE.txt`` file in the root of this repository. Code belonging to other open source projects is licensed under the respective licenses of those projects.
