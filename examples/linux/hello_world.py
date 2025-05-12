from int3 import Compiler, execute

cc = Compiler.from_str("linux/x86_64")
status = cc.sys_write(1, b"Hello, world!")
cc.sys_exit(status)

execute(cc.compile())
