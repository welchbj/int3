from int3 import Compiler

cc = Compiler.from_str("linux/x86_64", bad_bytes=b"\x00")

from llvmlite import ir as llvmir

# @cc.func()
# def my_func(x: int) -> int:
#     return x + 1


with cc.func.main(return_type=int):
    # TODO: Could this be overloaded __add__?
    var_one = cc.add(cc.i(0xDEAD0000), cc.i(0x0000BEEF))
    var_two = var_one + 123

    print(f"{var_one = }")
    print(f"{var_two = }")

    cc.ret(var_two)

    # with cc.if_else(my_var < 0xCAFEBABE) as (if_, else_):
    #     with if_:
    #         cc.sys_exit(0)
    #     with else_:
    #         cc.sys_exit(1)


sep = "=" * 80 + "\n"
print(cc.llvm_ir())
print(sep)
print(cc.asm())
