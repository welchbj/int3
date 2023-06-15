from dataclasses import dataclass, field

from int3.builder import Builder
from int3.emission import WindowsEmitter, Windowsx86Emitter

from .payload import Payload


@dataclass
class MessageBoxPayload(Payload):
    emitter: WindowsEmitter = field(init=False)

    def __post_init__(self):
        # TODO: Set emitter based on the ctx's architecture.
        self.emitter = Windowsx86Emitter(ctx=self.ctx)

    @classmethod
    def name(cls) -> str:
        return "windows/message_box"

    def __str__(self) -> str:
        builder = Builder()

        builder += self.emitter.mov("eax", "ebx")
        builder += self.emitter.push("ebx")

        return str(builder)
