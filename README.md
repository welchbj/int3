# int3

## Synopsis

`int3` is a Python toolkit for writing low-level, position-independent code featuring the following...

A high-level command-line interface for common assembly tasks:

```sh
$ echo -n "int3" | int3 assemble -a x86_64 | int3 format
b"\xcc"
```

A Python interface for writing your own position-independent programs ([`examples/linux/hello_world.py`](examples/linux/hello_world.py)):

```python
import sys

from int3 import Compiler

cc = Compiler.from_str("linux/x86_64", bad_bytes=b"\n\r")

with cc.def_func.main():
    num_written = cc.sys_write(fd=1, buf=b"Hello, world\n")
    cc.sys_exit(num_written)

sys.stdout.buffer.write(cc.compile())
```

Support for disassembling them:

```sh
$ python3 examples/linux/hello_world.py | python3 -m int3 disassemble | tail -10
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
```

And executing them:

```sh
$ python3 examples/linux/hello_world.py | python3 -m int3 execute ; echo $?
Hello, world
13
```

## Installation

int3 is tested on the latest major version of CPython. You can get the latest release from PyPI with:

```sh
pip install int3
```

## Features

* Write position-independent assembly code in a higher-level Python interface
* Builtin support for cross-compiling to various architectures
* Mutate generated machine code to remove bad bytes
* Command-line interface for common formatting and exploratory reversing tasks

## License & Usage

`int3` is intended for educational use. `int3`'s unique code is released under the [GNU LGPLv3](https://choosealicense.com/licenses/lgpl-3.0), as per the [`LICENSE.txt`](LICENSE.txt) file in the root of this repository. Code belonging to other open source projects is licensed under the respective licenses of those projects.
