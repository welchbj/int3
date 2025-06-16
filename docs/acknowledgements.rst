================
Acknowledgements
================

Vendored Projects
-----------------

Some code and data from other open source projects is `vendored <https://stackoverflow.com/questions/26217488/what-is-vendoring>`_ within the ``int3`` repository. The code for each of these open source projects is governed by the respective licensing terms of the respective project. These vendored projects include:

* Syscall number tables from the `syscall-tables <https://github.com/hrw/syscalls-table>`_ project
* LLVM IR code generation and interfacing with the LLVM API via a modified version of the `llvmlite <https://github.com/numba/llvmlite>`_ project


Dependencies
------------

``int3`` stands on the shoulders of several projects (in addition to those vendored directly in the codebase):

* `LLVM <https://llvm.org/>`_
* `Keystone assembler <https://www.keystone-engine.org/>`_
* `Capstone disassembler <https://www.capstone-engine.org/>`_
* `Z3 solver <https://github.com/Z3Prover/z3>`_
