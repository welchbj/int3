import sys

from int3 import Compiler

cc = Compiler.from_str("linux/x86_64", bad_bytes=b"\x00", load_addr=0xBEEF0000)

with cc.def_func.main():
    num_written = cc.sys_write(fd=1, buf=b"Hello, world\n")
    cc.sys_exit(num_written)

sys.stdout.buffer.write(cc.compile())
