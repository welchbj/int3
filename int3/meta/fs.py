from pathlib import Path


class Int3Files:
    ProjectRootDir = Path(__file__).resolve().parent.parent.parent

    Int3SrcDir = ProjectRootDir / "int3"
    SyscallTablesDir = Int3SrcDir / "platform" / "linux" / "syscalls" / "tables"
