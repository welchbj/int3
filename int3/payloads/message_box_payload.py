from dataclasses import dataclass

from int3.builder import Builder
from int3.emission import Windowsx86Emitter

from .payload import Payload


@dataclass
class MessageBoxPayload(Payload):
    @classmethod
    def name(cls) -> str:
        return "windows/message_box"

    def __str__(self) -> str:
        builder = Builder()

        emitter = Windowsx86Emitter(ctx=self.ctx)

        builder += emitter.mov("ecx", 0x41414141)
        builder += emitter.mov("eax", "ebx")
        builder += emitter.push("ebx")

        return str(builder)
