# int3

## Synopsis

`int3` is a Python library and command-line tool for generating, transforming, and encoding shellcode payloads:

```sh
echo -n "int3" | int3 assemble | int3 format
b"\xcc"
```

This library's initial release is focused on Windows 32-bit and 64-bit environments.

## Installation

`int3` is available on PyPI. Install it with your favorite Python packaging manager. For example:

```sh
pip install int3
```

## Usage

TODO

## Design

TODO

### Workflow

TODO

### Relationship with LLVM IR

```
https://llvmlite.readthedocs.io/en/latest/user-guide/ir/index.html
https://mcyoung.xyz/2023/08/01/llvm-ir/
https://docs.angr.io/en/latest/faq.html#why-did-you-choose-vex-instead-of-another-ir-such-as-llvm-reil-bap-etc
https://github.com/lifting-bits/mcsema?tab=readme-ov-file#comparison-with-other-machine-code-to-llvm-bitcode-lifters
```

## Development

### Environment Setup

#### System Dependencies

The following command will install requisite system dependencies:

```sh
sudo apt-get install cmake qemu-user
```

Please note that this step must precede the Python dependency installation step.

In order to run tests and build some utilities, a suite of cross-compilation toolchains is required. These can be downloaded from [`musl.cc`](https://musl.cc) by invoking the following script (it may take a while):

```sh
./scripts/install_musl_cc_toolchains.sh
```

#### Python Dependencies

This project uses [Poetry](https://python-poetry.org) to manage its Python dependencies. Follow [the Poetry installation instructions](https://python-poetry.org/docs/#installing-with-the-official-installer) for its setup.

You can then install this project's Python dependencies with:

```sh
poetry install
```

### Releases

Assuming [Poetry credentials are properly setup](https://python-poetry.org/docs/repositories/#configuring-credentials), publishing to PyPI should be simple:

```sh
poetry publish --build
```

### Debugging

Testing shellcode payloads compatible with the host platform and architecture can be done with GDB (assuming the payload has a breakpoint embdedded within it):

```sh
x=$(mktemp) ; python3 -m int3 payload --payload linux/reverse_shell --strategy CodeSize --bad-bytes "\x41\x42\x43\x00\x01\x02" --format-out Raw > $x ; gdb -ex "handle SIGUSR1 nostop" -ex "run" --args python -m int3 execute --input $x
```

## License

`int3` is intended for educational purposes and events such as CTFs only. It should never be used to target machines and/or networks without explicit prior consent. `int3`'s unique code is released under the [MIT license](https://opensource.org/licenses/MIT), as per the [`LICENSE.txt`](./LICENSE.txt) file.

## References

### Vendored Projects

Some code and data from other open source projects is [vendored](https://stackoverflow.com/questions/26217488/what-is-vendoring) within the `int3` repository. This includes:

* Syscall number tables from the [`syscall-tables`](https://github.com/hrw/syscalls-table) project.

### Knowledge References

Many helpful resources were used in the development of this tool, including:

* [Capstone Python documentation](https://www.capstone-engine.org/lang_python.html)
* [Phrack - Writing ia32 alphanumeric shellcodes](http://phrack.org/issues/57/15.html)
* [MazeGen's x86 reference](http://ref.x86asm.net/coder32.html)
* [NASM](https://www.nasm.us/)
