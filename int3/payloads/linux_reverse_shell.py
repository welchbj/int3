from dataclasses import dataclass

from int3.emission import Linuxx86_64Emitter

from .payload import Payload


@dataclass
class LinuxReverseShell(Payload):
    @classmethod
    def name(cls) -> str:
        return "linux/reverse_shell"

    def __str__(self) -> str:
        emitter = Linuxx86_64Emitter(ctx=self.ctx)

        emitter.mov("rcx", 0x41414141)
        # emitter.mov("rax", "rbx")
        # emitter.push("rbx")

        return str(emitter)
