from int3 import Compiler

cc = Compiler.from_str("linux/x86_64", bad_bytes=b"\x00\xca")

with cc.func.main():
    my_var = cc.i()
    cc.mov(my_var, 0xDEADBEEF)

    with cc.if_else(my_var < 0xCAFEBABE) as (if_, else_):
        with if_:
            cc.sys_exit(0)
        with else_:
            cc.sys_exit(1)

sep = "=" * 80 + "\n"
print("HLIR")
print("~~~~")
print(cc.hlir_str())
print(sep)
print("LLIR")
print("~~~~")
print(cc.llir_str())
