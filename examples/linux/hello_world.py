from int3 import Compiler

cc = Compiler.from_str("linux/x86_64", bad_bytes=b"\x00")

with cc.func.main():
    my_var = cc.i()
    cc.mov(my_var, 0xDEADBEEF)

    with cc.if_else(my_var < 0xCAFEBABE) as (if_, else_):
        with if_:
            cc.sys_exit(0)
        with else_:
            cc.sys_exit(1)

print(cc.ir_str())
print("=" * 80)
print(cc.flatten())
