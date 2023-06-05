# int3

## Synopsis

`int3` is a Python library and command-line tool for generating and encoding binary payloads.by writing them word-by-word to the stack. Its initial release is focused on Windows 32-bit and 64-bit shellcoding.

## Installation

`int3` is available on PyPI. Install it with your favorite Python packaging manager. For example:

```sh
pip install int3
```

## Usage

### Formatting

TODO

### Encoding

TODO

### Factoring

TODO

## Development

### Environment Setup

#### System Dependencies

The following command will install requisite system dependencies:

```sh
sudo apt-get install cmake
```

Please note that this step must precede the Python dependency installation step.

#### Python Dependencies

This project uses [Poetry](https://python-poetry.org) to manage its Python dependencies. Follow [the Poetry installation instructions](https://python-poetry.org/docs/#installing-with-the-official-installer) for its setup.

You can then install this project's Python dependencies with:

```sh
poetry install
```

### Releases

Assuming [Poetry credentials are properly setup](https://python-poetry.org/docs/repositories/#configuring-credentials), publishing to PyPI should be simple:

```sh
poetry publish
```

## License

`int3` is intended for educational purposes and events such as CTFs only. It should never be used to target machines and/or networks without explicit prior consent. This code is released under the [MIT license](https://opensource.org/licenses/MIT), as per the [`LICENSE.txt`](./LICENSE.txt) file.

## References

Many helpful resources were used in the development of this tool, including:

* [Phrack - Writing ia32 alphanumeric shellcodes](http://phrack.org/issues/57/15.html)
* [MazeGen's x86 reference](http://ref.x86asm.net/coder32.html)
* [NASM](https://www.nasm.us/)
