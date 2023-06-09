from dataclasses import dataclass, field

from int3.architectures import Architectures
from int3.errors import Int3UnsupportedArchitecture, Int3UnsupportedPlatform
from int3.platforms import Platforms
from int3.register import Register

from .emitter import Emitter
from .emission import Emission
from .x86_emitter import x86Emitter
from .x86_64_emitter import x86_64Emitter


@dataclass
class WindowsEmitter(Emitter):
    asm_emitter: x86Emitter | x86_64Emitter = field(init=False)

    def __post_init__(self):
        if self.ctx.platform is not Platforms.Windows:
            raise Int3UnsupportedPlatform(
                f"{self.__class__.__qualname__} only supports the Windows platform"
            )

        match arch := self.ctx.architecture:
            case Architectures.x86.value:
                self.asm_emitter = x86Emitter(ctx=self.ctx)
            case Architectures.x86_64.value:
                self.asm_emitter = x86_64Emitter(ctx=self.ctx)
            case _:
                raise Int3UnsupportedArchitecture(
                    f"{self.__class__.__qualname__} does not support architecture "
                    f"{arch}"
                )

    # TODO: Other primitive utilities.

    def resolve_function(
        self, func_name: str, result: Register, use_hash: bool = True
    ) -> Emission:
        # TODO
        pass
