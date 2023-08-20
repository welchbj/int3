from dataclasses import dataclass

from int3.emission import LinuxEmitter
from int3.registers import Registers

from .payload import Payload


@dataclass
class LinuxReverseShell(Payload[Registers]):
    host: str
    port: int

    @classmethod
    def name(cls) -> str:
        return "linux/reverse_shell"

    def compile(self) -> str:
        emitter = LinuxEmitter[Registers].get_emitter(self.ctx.architecture, self.ctx)

        # TODO
        emitter.echo(self.host.encode())

        return str(emitter)
