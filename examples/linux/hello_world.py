import sys

from int3 import Compiler

cc = Compiler.from_str("linux/x86_64", bad_bytes=b"\x00")


# @cc.func()
# def my_func(x: int) -> int:
#     return x + 1


with cc.func.main(return_type=int):
    var_one = cc.i(0xDEAD0000) + 0x0000BEEF
    var_two = var_one + 123

    cc.ret(var_two)

    # with cc.if_else(my_var < 0xCAFEBABE) as (if_, else_):
    #     with if_:
    #         cc.sys_exit(0)
    #     with else_:
    #         cc.sys_exit(1)


sep = "=" * 80 + "\n"
print(cc.llvm_ir(), file=sys.stderr)
print(sep, file=sys.stderr)
print(cc.to_asm(), file=sys.stderr)
print(sep, file=sys.stderr)
sys.stdout.buffer.write(cc.to_bytes())
