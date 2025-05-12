from typing import overload, TYPE_CHECKING, Literal, Type, TypeVar

from int3.architecture import Architectures
from int3.errors import Int3ArgumentError


if TYPE_CHECKING:
    from .compiler import Compiler
    from ._linux_compiler import LinuxCompiler


T = TypeVar("T", bound="Compiler")


class CompilerFactoryMixin:
    @overload
    @classmethod
    def from_str(cls: Type[T], platform_spec: Literal["linux/x86_64"]) -> "LinuxCompiler": ...

    @classmethod
    def from_str(cls: Type[T], platform_spec: str) -> T:
        parts = platform_spec.split("/")
        if len(parts) != 2:
            raise Int3ArgumentError(f"Invalid platform spec: {platform_spec}")

        os_name = parts[0]
        match os_name.lower():
            case "linux":
                compiler_cls = LinuxCompiler
            case "windows":
                raise NotImplementedError(f"Windows support not yet implemented")
            case _:
                raise Int3ArgumentError(f"Unknown platform string {os_name}")

        arch = Architectures.from_str(parts[1])
        return compiler_cls(arch)
