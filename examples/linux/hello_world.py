import sys

from int3 import Compiler

cc = Compiler.from_str("linux/x86_64", bad_bytes=b"\x00")

with cc.func.increment(int, int):
    cc.ret(cc.args[0] + 1)

with cc.func.main():
    var = cc.i(0xDEAD) + 0xBEEF
    result = cc.func.increment(var)
    cc.sys_exit(result)

sys.stdout.buffer.write(cc.compile())
