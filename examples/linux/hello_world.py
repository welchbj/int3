import sys

from int3 import Compiler

cc = Compiler.from_str("linux/x86_64")

with cc.def_func.increment(int, int):
    cc.ret(cc.args[0] + 1)

with cc.def_func.main():
    msg = cc.b(b"Hello, world")
    num_written = cc.sys_write(fd=1, buf=msg)
    cc.sys_exit(num_written)

sys.stdout.buffer.write(cc.compile())
