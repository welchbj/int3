from pathlib import Path


class Int3Files:
    PROJECT_ROOT_DIR = Path(__file__).resolve().parent.parent

    INT3_SRC_DIR = PROJECT_ROOT_DIR / "int3"
    SYSCALL_TABLES_DIR = INT3_SRC_DIR / "syscalls" / "tables"
