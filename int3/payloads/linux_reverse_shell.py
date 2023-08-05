from dataclasses import dataclass

from int3.emission import Linuxx86_64Emitter

from .payload import Payload


@dataclass
class LinuxReverseShell(Payload):
    @classmethod
    def name(cls) -> str:
        return "linux/reverse_shell"

    def __str__(self) -> str:
        # TODO: These need to be passable from the user.
        host, port = b"127.0.0.1", 55555

        emitter = Linuxx86_64Emitter(ctx=self.ctx)

        emitter.syscall(0, "rax")

        emitter.mov("rdx", 0)
        emitter.mov("rcx", 0x43434343)
        emitter.mov("rcx", 0x4141414142)

        emitter.syscall(0, 1000, "rbx")
        emitter.echo(host)

        return str(emitter)
