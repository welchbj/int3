import sys

from int3 import Compiler

cc = Compiler.from_str("linux/x86_64")

with cc.def_func.main():
    num_written = cc.sys_write(fd=1, buf=b"Hello, world")
    cc.sys_exit(num_written)

sys.stdout.buffer.write(cc.compile())
