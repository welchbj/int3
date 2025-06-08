===========
Development
===========

Environment Setup
-----------------

Install required Python packages and activate the corresponding virtual environment with:

.. code-block:: bash

    uv sync
    source .venv/bin/activate


Releases
--------

The PyPI package can be published with:

.. code-block:: bash

    uv publish


Testing and Code Quality
------------------------

Linting and testing checks is performed with:

.. code-block:: bash

    ./scripts/lint.sh

The code is automatically formatted with:

.. code-block:: bash

    ./scripts/format.sh


Debugging
---------

Testing shellcode payloads compatible with the host platform and architecture can be done with GDB (assuming the payload has a breakpoint embdedded within it):

.. code-block:: bash

    x=$(mktemp) ; python3 examples/linux/hello_world.py > $x ; gdb -ex "handle SIGUSR1 nostop" -ex "run" --args python -m int3 execute --input $x
