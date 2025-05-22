from int3 import Compiler

cc = Compiler.from_str("linux/x86_64", bad_bytes=b"\x00")


with cc.func.main():
    my_var = cc.i(0xDEADBEEF)
    cc.mov(my_var, 0xD00D)

    with cc.if_else(my_var < 0xCAFEBABE) as (if_, else_):
        with if_:
            cc.sys_exit(0)
        with else_:
            cc.sys_exit(1)

    # status = cc.sys_write(1, b"Hello, world!")

print(cc.ir_str())
print("=" * 80)
# print(cc.compile())
