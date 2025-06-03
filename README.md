# int3

## Synopsis

`int3` is a Python library and command-line tool for writing and working with shellcode:

```sh
echo -n "int3" | int3 assemble | int3 format
b"\xcc"
```

## Installation

`int3` is available on PyPI. Install it with your favorite Python packaging manager. For example:

```sh
pip install int3
```

## License

`int3` is should never be used to target machines and/or networks without explicit prior consent. `int3`'s unique code is released under the [GPLv2 license](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html), as per the [`LICENSE.txt`](./LICENSE.txt) file.

## Usage

TODO

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

Install required Python packages and activate the corresponding virtual environment with:

```sh
uv sync
source .venv/bin/activate
```

### Releases

The PyPI package can be published with:

```sh
uv publish
```

### Debugging

Testing shellcode payloads compatible with the host platform and architecture can be done with GDB (assuming the payload has a breakpoint embdedded within it):

```sh
x=$(mktemp) ; python3 examples/linux/hello_world.py > $x ; gdb -ex "handle SIGUSR1 nostop" -ex "run" --args python -m int3 execute --input $x
```

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
* [`angr` library discussion on VEX IR](https://docs.angr.io/en/latest/faq.html#why-did-you-choose-vex-instead-of-another-ir-such-as-llvm-reil-bap-etc)
