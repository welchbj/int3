from int3 import Compiler

cc = Compiler.from_str("linux/x86_64", bad_bytes=b"\x00")

from llvmlite import ir as llvmir

with cc.func.main(func_type=llvmir.FunctionType(return_type=cc.types.i32, args=[])):
    # TODO: Could this be overloaded __add__?
    var_one = cc.add(cc.i32(0xDEAD0000), cc.i32(0x0000BEEF))
    var_two = cc.add(var_one, cc.i32(123))

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
print(cc.compile_to_asm())
