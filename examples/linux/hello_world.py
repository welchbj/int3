import sys

from int3 import Compiler

cc = Compiler.from_str("linux/x86_64")

with cc.def_func.increment(int, int):
    cc.ret(cc.args[0] + 1)

with cc.def_func.main():
    var = cc.i64(0xDEAD) + 0xBEEF
    result = cc.call.increment(var)
    cc.sys_exit(result)

sys.stdout.buffer.write(cc.compile())
