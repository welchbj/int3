===========
Development
===========

Environment Setup
-----------------

To setup the full development environment on a Debian-based system, some additional system packages are needed:

.. code-block:: bash

    sudo apt-get install qemu-user build-essential git

Install required Python packages and activate the corresponding virtual environment with:

.. code-block:: bash

    uv sync
    source .venv/bin/activate

Install cross-compilation toolchains from the excellent `musl.cc project <https://musl.cc/>`_:

.. code-block:: bash

    ./scripts/install_musl_cc_toolchains.sh


Custom ``llvmlite`` Build
-------------------------

In order to expose the full suite of LLVM's supported architecture assembly parsers (a requirement in order to parse generated inline assembly in LLVM IR code), a few adjustments to the `llvmlite` code base are required. ``llvmlite`` discusses how to do so `here <https://llvmlite.readthedocs.io/en/latest/admin-guide/install.html>`_.

This process requires having `Miniconda <https://www.anaconda.com/docs/getting-started/miniconda/main>`_ installed, in order to download LLVM builds that ``llvmlite`` in turn depends on. Before following the below steps, you should consult the `Anaconda Terms of Service <https://www.anaconda.com/legal>`_ to ensure your work falls within scope of their free platform use.

For Linux installation of Miniconda, following the instructions `here <https://www.anaconda.com/docs/getting-started/miniconda/install#linux-terminal-installer>`_.

.. warning::

    The automation tooling in this repo assumes you install Miniconda at ``~/miniconda3``.

For the sake of convenience, building and copying over a modified `llvmlite` tree into the `int3` source tree can be accomplished with:

.. code-block:: bash

    ./scripts/install_custom_llvmlite.sh --python-version 3.13 --build-name dev


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
