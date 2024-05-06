from dataclasses import dataclass, field
from pathlib import Path

from int3.errors import Int3UnsupportedSyscall


@dataclass(frozen=True)
class LinuxSyscallNumbers:
    table_file_path: str | Path

    _lookup_map: dict[str, int | None] = field(init=False, default_factory=dict)

    def __post_init__(self):
        object.__setattr__(
            self, "_lookup_map", self._parse_syscall_table(Path(self.table_file_path))
        )

    def _parse_syscall_table(self, table_file_path: Path) -> dict[str, int | None]:
        lookup_map = {}

        with Path(table_file_path).open("r") as f:
            for line in f:
                values = line.strip().split()

                syscall_name = values[0]
                if len(values) > 1:
                    syscall_num = int(values[1])
                else:
                    syscall_num = None

                lookup_map[syscall_name] = syscall_num

        return lookup_map

    def _lookup(self, syscall_name: str) -> int:
        syscall_number = self._lookup_map.get(syscall_name, None)
        if syscall_number is None:
            raise Int3UnsupportedSyscall(f"No syscall number for {syscall_name}")

        return syscall_number

    @property
    def _llseek(self) -> int:
        return self._lookup("_llseek")

    @property
    def _newselect(self) -> int:
        return self._lookup("_newselect")

    @property
    def _sysctl(self) -> int:
        return self._lookup("_sysctl")

    @property
    def accept(self) -> int:
        return self._lookup("accept")

    @property
    def accept4(self) -> int:
        return self._lookup("accept4")

    @property
    def access(self) -> int:
        return self._lookup("access")

    @property
    def acct(self) -> int:
        return self._lookup("acct")

    @property
    def add_key(self) -> int:
        return self._lookup("add_key")

    @property
    def adjtimex(self) -> int:
        return self._lookup("adjtimex")

    @property
    def alarm(self) -> int:
        return self._lookup("alarm")

    @property
    def arc_gettls(self) -> int:
        return self._lookup("arc_gettls")

    @property
    def arc_settls(self) -> int:
        return self._lookup("arc_settls")

    @property
    def arc_usr_cmpxchg(self) -> int:
        return self._lookup("arc_usr_cmpxchg")

    @property
    def arch_prctl(self) -> int:
        return self._lookup("arch_prctl")

    @property
    def arm_fadvise64_64(self) -> int:
        return self._lookup("arm_fadvise64_64")

    @property
    def atomic_barrier(self) -> int:
        return self._lookup("atomic_barrier")

    @property
    def atomic_cmpxchg_32(self) -> int:
        return self._lookup("atomic_cmpxchg_32")

    @property
    def bdflush(self) -> int:
        return self._lookup("bdflush")

    @property
    def bind(self) -> int:
        return self._lookup("bind")

    @property
    def bpf(self) -> int:
        return self._lookup("bpf")

    @property
    def brk(self) -> int:
        return self._lookup("brk")

    @property
    def cachectl(self) -> int:
        return self._lookup("cachectl")

    @property
    def cacheflush(self) -> int:
        return self._lookup("cacheflush")

    @property
    def cachestat(self) -> int:
        return self._lookup("cachestat")

    @property
    def capget(self) -> int:
        return self._lookup("capget")

    @property
    def capset(self) -> int:
        return self._lookup("capset")

    @property
    def chdir(self) -> int:
        return self._lookup("chdir")

    @property
    def chmod(self) -> int:
        return self._lookup("chmod")

    @property
    def chown(self) -> int:
        return self._lookup("chown")

    @property
    def chown32(self) -> int:
        return self._lookup("chown32")

    @property
    def chroot(self) -> int:
        return self._lookup("chroot")

    @property
    def clock_adjtime(self) -> int:
        return self._lookup("clock_adjtime")

    @property
    def clock_adjtime64(self) -> int:
        return self._lookup("clock_adjtime64")

    @property
    def clock_getres(self) -> int:
        return self._lookup("clock_getres")

    @property
    def clock_getres_time64(self) -> int:
        return self._lookup("clock_getres_time64")

    @property
    def clock_gettime(self) -> int:
        return self._lookup("clock_gettime")

    @property
    def clock_gettime64(self) -> int:
        return self._lookup("clock_gettime64")

    @property
    def clock_nanosleep(self) -> int:
        return self._lookup("clock_nanosleep")

    @property
    def clock_nanosleep_time64(self) -> int:
        return self._lookup("clock_nanosleep_time64")

    @property
    def clock_settime(self) -> int:
        return self._lookup("clock_settime")

    @property
    def clock_settime64(self) -> int:
        return self._lookup("clock_settime64")

    @property
    def clone(self) -> int:
        return self._lookup("clone")

    @property
    def clone2(self) -> int:
        return self._lookup("clone2")

    @property
    def clone3(self) -> int:
        return self._lookup("clone3")

    @property
    def close(self) -> int:
        return self._lookup("close")

    @property
    def close_range(self) -> int:
        return self._lookup("close_range")

    @property
    def connect(self) -> int:
        return self._lookup("connect")

    @property
    def copy_file_range(self) -> int:
        return self._lookup("copy_file_range")

    @property
    def creat(self) -> int:
        return self._lookup("creat")

    @property
    def create_module(self) -> int:
        return self._lookup("create_module")

    @property
    def delete_module(self) -> int:
        return self._lookup("delete_module")

    @property
    def dipc(self) -> int:
        return self._lookup("dipc")

    @property
    def dup(self) -> int:
        return self._lookup("dup")

    @property
    def dup2(self) -> int:
        return self._lookup("dup2")

    @property
    def dup3(self) -> int:
        return self._lookup("dup3")

    @property
    def epoll_create(self) -> int:
        return self._lookup("epoll_create")

    @property
    def epoll_create1(self) -> int:
        return self._lookup("epoll_create1")

    @property
    def epoll_ctl(self) -> int:
        return self._lookup("epoll_ctl")

    @property
    def epoll_ctl_old(self) -> int:
        return self._lookup("epoll_ctl_old")

    @property
    def epoll_pwait(self) -> int:
        return self._lookup("epoll_pwait")

    @property
    def epoll_pwait2(self) -> int:
        return self._lookup("epoll_pwait2")

    @property
    def epoll_wait(self) -> int:
        return self._lookup("epoll_wait")

    @property
    def epoll_wait_old(self) -> int:
        return self._lookup("epoll_wait_old")

    @property
    def eventfd(self) -> int:
        return self._lookup("eventfd")

    @property
    def eventfd2(self) -> int:
        return self._lookup("eventfd2")

    @property
    def exec_with_loader(self) -> int:
        return self._lookup("exec_with_loader")

    @property
    def execv(self) -> int:
        return self._lookup("execv")

    @property
    def execve(self) -> int:
        return self._lookup("execve")

    @property
    def execveat(self) -> int:
        return self._lookup("execveat")

    @property
    def exit(self) -> int:
        return self._lookup("exit")

    @property
    def exit_group(self) -> int:
        return self._lookup("exit_group")

    @property
    def faccessat(self) -> int:
        return self._lookup("faccessat")

    @property
    def faccessat2(self) -> int:
        return self._lookup("faccessat2")

    @property
    def fadvise64(self) -> int:
        return self._lookup("fadvise64")

    @property
    def fadvise64_64(self) -> int:
        return self._lookup("fadvise64_64")

    @property
    def fallocate(self) -> int:
        return self._lookup("fallocate")

    @property
    def fanotify_init(self) -> int:
        return self._lookup("fanotify_init")

    @property
    def fanotify_mark(self) -> int:
        return self._lookup("fanotify_mark")

    @property
    def fchdir(self) -> int:
        return self._lookup("fchdir")

    @property
    def fchmod(self) -> int:
        return self._lookup("fchmod")

    @property
    def fchmodat(self) -> int:
        return self._lookup("fchmodat")

    @property
    def fchown(self) -> int:
        return self._lookup("fchown")

    @property
    def fchown32(self) -> int:
        return self._lookup("fchown32")

    @property
    def fchownat(self) -> int:
        return self._lookup("fchownat")

    @property
    def fcntl(self) -> int:
        return self._lookup("fcntl")

    @property
    def fcntl64(self) -> int:
        return self._lookup("fcntl64")

    @property
    def fdatasync(self) -> int:
        return self._lookup("fdatasync")

    @property
    def fgetxattr(self) -> int:
        return self._lookup("fgetxattr")

    @property
    def finit_module(self) -> int:
        return self._lookup("finit_module")

    @property
    def flistxattr(self) -> int:
        return self._lookup("flistxattr")

    @property
    def flock(self) -> int:
        return self._lookup("flock")

    @property
    def fork(self) -> int:
        return self._lookup("fork")

    @property
    def fp_udfiex_crtl(self) -> int:
        return self._lookup("fp_udfiex_crtl")

    @property
    def fremovexattr(self) -> int:
        return self._lookup("fremovexattr")

    @property
    def fsconfig(self) -> int:
        return self._lookup("fsconfig")

    @property
    def fsetxattr(self) -> int:
        return self._lookup("fsetxattr")

    @property
    def fsmount(self) -> int:
        return self._lookup("fsmount")

    @property
    def fsopen(self) -> int:
        return self._lookup("fsopen")

    @property
    def fspick(self) -> int:
        return self._lookup("fspick")

    @property
    def fstat(self) -> int:
        return self._lookup("fstat")

    @property
    def fstat64(self) -> int:
        return self._lookup("fstat64")

    @property
    def fstatat64(self) -> int:
        return self._lookup("fstatat64")

    @property
    def fstatfs(self) -> int:
        return self._lookup("fstatfs")

    @property
    def fstatfs64(self) -> int:
        return self._lookup("fstatfs64")

    @property
    def fsync(self) -> int:
        return self._lookup("fsync")

    @property
    def ftruncate(self) -> int:
        return self._lookup("ftruncate")

    @property
    def ftruncate64(self) -> int:
        return self._lookup("ftruncate64")

    @property
    def futex(self) -> int:
        return self._lookup("futex")

    @property
    def futex_time64(self) -> int:
        return self._lookup("futex_time64")

    @property
    def futex_waitv(self) -> int:
        return self._lookup("futex_waitv")

    @property
    def futimesat(self) -> int:
        return self._lookup("futimesat")

    @property
    def get_kernel_syms(self) -> int:
        return self._lookup("get_kernel_syms")

    @property
    def get_mempolicy(self) -> int:
        return self._lookup("get_mempolicy")

    @property
    def get_robust_list(self) -> int:
        return self._lookup("get_robust_list")

    @property
    def get_thread_area(self) -> int:
        return self._lookup("get_thread_area")

    @property
    def getcpu(self) -> int:
        return self._lookup("getcpu")

    @property
    def getcwd(self) -> int:
        return self._lookup("getcwd")

    @property
    def getdents(self) -> int:
        return self._lookup("getdents")

    @property
    def getdents64(self) -> int:
        return self._lookup("getdents64")

    @property
    def getdomainname(self) -> int:
        return self._lookup("getdomainname")

    @property
    def getdtablesize(self) -> int:
        return self._lookup("getdtablesize")

    @property
    def getegid(self) -> int:
        return self._lookup("getegid")

    @property
    def getegid32(self) -> int:
        return self._lookup("getegid32")

    @property
    def geteuid(self) -> int:
        return self._lookup("geteuid")

    @property
    def geteuid32(self) -> int:
        return self._lookup("geteuid32")

    @property
    def getgid(self) -> int:
        return self._lookup("getgid")

    @property
    def getgid32(self) -> int:
        return self._lookup("getgid32")

    @property
    def getgroups(self) -> int:
        return self._lookup("getgroups")

    @property
    def getgroups32(self) -> int:
        return self._lookup("getgroups32")

    @property
    def gethostname(self) -> int:
        return self._lookup("gethostname")

    @property
    def getitimer(self) -> int:
        return self._lookup("getitimer")

    @property
    def getpagesize(self) -> int:
        return self._lookup("getpagesize")

    @property
    def getpeername(self) -> int:
        return self._lookup("getpeername")

    @property
    def getpgid(self) -> int:
        return self._lookup("getpgid")

    @property
    def getpgrp(self) -> int:
        return self._lookup("getpgrp")

    @property
    def getpid(self) -> int:
        return self._lookup("getpid")

    @property
    def getpmsg(self) -> int:
        return self._lookup("getpmsg")

    @property
    def getppid(self) -> int:
        return self._lookup("getppid")

    @property
    def getpriority(self) -> int:
        return self._lookup("getpriority")

    @property
    def getrandom(self) -> int:
        return self._lookup("getrandom")

    @property
    def getresgid(self) -> int:
        return self._lookup("getresgid")

    @property
    def getresgid32(self) -> int:
        return self._lookup("getresgid32")

    @property
    def getresuid(self) -> int:
        return self._lookup("getresuid")

    @property
    def getresuid32(self) -> int:
        return self._lookup("getresuid32")

    @property
    def getrlimit(self) -> int:
        return self._lookup("getrlimit")

    @property
    def getrusage(self) -> int:
        return self._lookup("getrusage")

    @property
    def getsid(self) -> int:
        return self._lookup("getsid")

    @property
    def getsockname(self) -> int:
        return self._lookup("getsockname")

    @property
    def getsockopt(self) -> int:
        return self._lookup("getsockopt")

    @property
    def gettid(self) -> int:
        return self._lookup("gettid")

    @property
    def gettimeofday(self) -> int:
        return self._lookup("gettimeofday")

    @property
    def getuid(self) -> int:
        return self._lookup("getuid")

    @property
    def getuid32(self) -> int:
        return self._lookup("getuid32")

    @property
    def getunwind(self) -> int:
        return self._lookup("getunwind")

    @property
    def getxattr(self) -> int:
        return self._lookup("getxattr")

    @property
    def getxgid(self) -> int:
        return self._lookup("getxgid")

    @property
    def getxpid(self) -> int:
        return self._lookup("getxpid")

    @property
    def getxuid(self) -> int:
        return self._lookup("getxuid")

    @property
    def idle(self) -> int:
        return self._lookup("idle")

    @property
    def init_module(self) -> int:
        return self._lookup("init_module")

    @property
    def inotify_add_watch(self) -> int:
        return self._lookup("inotify_add_watch")

    @property
    def inotify_init(self) -> int:
        return self._lookup("inotify_init")

    @property
    def inotify_init1(self) -> int:
        return self._lookup("inotify_init1")

    @property
    def inotify_rm_watch(self) -> int:
        return self._lookup("inotify_rm_watch")

    @property
    def io_cancel(self) -> int:
        return self._lookup("io_cancel")

    @property
    def io_destroy(self) -> int:
        return self._lookup("io_destroy")

    @property
    def io_getevents(self) -> int:
        return self._lookup("io_getevents")

    @property
    def io_pgetevents(self) -> int:
        return self._lookup("io_pgetevents")

    @property
    def io_pgetevents_time64(self) -> int:
        return self._lookup("io_pgetevents_time64")

    @property
    def io_setup(self) -> int:
        return self._lookup("io_setup")

    @property
    def io_submit(self) -> int:
        return self._lookup("io_submit")

    @property
    def io_uring_enter(self) -> int:
        return self._lookup("io_uring_enter")

    @property
    def io_uring_register(self) -> int:
        return self._lookup("io_uring_register")

    @property
    def io_uring_setup(self) -> int:
        return self._lookup("io_uring_setup")

    @property
    def ioctl(self) -> int:
        return self._lookup("ioctl")

    @property
    def ioperm(self) -> int:
        return self._lookup("ioperm")

    @property
    def iopl(self) -> int:
        return self._lookup("iopl")

    @property
    def ioprio_get(self) -> int:
        return self._lookup("ioprio_get")

    @property
    def ioprio_set(self) -> int:
        return self._lookup("ioprio_set")

    @property
    def ipc(self) -> int:
        return self._lookup("ipc")

    @property
    def kcmp(self) -> int:
        return self._lookup("kcmp")

    @property
    def kern_features(self) -> int:
        return self._lookup("kern_features")

    @property
    def kexec_file_load(self) -> int:
        return self._lookup("kexec_file_load")

    @property
    def kexec_load(self) -> int:
        return self._lookup("kexec_load")

    @property
    def keyctl(self) -> int:
        return self._lookup("keyctl")

    @property
    def kill(self) -> int:
        return self._lookup("kill")

    @property
    def landlock_add_rule(self) -> int:
        return self._lookup("landlock_add_rule")

    @property
    def landlock_create_ruleset(self) -> int:
        return self._lookup("landlock_create_ruleset")

    @property
    def landlock_restrict_self(self) -> int:
        return self._lookup("landlock_restrict_self")

    @property
    def lchown(self) -> int:
        return self._lookup("lchown")

    @property
    def lchown32(self) -> int:
        return self._lookup("lchown32")

    @property
    def lgetxattr(self) -> int:
        return self._lookup("lgetxattr")

    @property
    def link(self) -> int:
        return self._lookup("link")

    @property
    def linkat(self) -> int:
        return self._lookup("linkat")

    @property
    def listen(self) -> int:
        return self._lookup("listen")

    @property
    def listxattr(self) -> int:
        return self._lookup("listxattr")

    @property
    def llistxattr(self) -> int:
        return self._lookup("llistxattr")

    @property
    def lookup_dcookie(self) -> int:
        return self._lookup("lookup_dcookie")

    @property
    def lremovexattr(self) -> int:
        return self._lookup("lremovexattr")

    @property
    def lseek(self) -> int:
        return self._lookup("lseek")

    @property
    def lsetxattr(self) -> int:
        return self._lookup("lsetxattr")

    @property
    def lstat(self) -> int:
        return self._lookup("lstat")

    @property
    def lstat64(self) -> int:
        return self._lookup("lstat64")

    @property
    def madvise(self) -> int:
        return self._lookup("madvise")

    @property
    def mbind(self) -> int:
        return self._lookup("mbind")

    @property
    def membarrier(self) -> int:
        return self._lookup("membarrier")

    @property
    def memfd_create(self) -> int:
        return self._lookup("memfd_create")

    @property
    def memfd_secret(self) -> int:
        return self._lookup("memfd_secret")

    @property
    def memory_ordering(self) -> int:
        return self._lookup("memory_ordering")

    @property
    def migrate_pages(self) -> int:
        return self._lookup("migrate_pages")

    @property
    def mincore(self) -> int:
        return self._lookup("mincore")

    @property
    def mkdir(self) -> int:
        return self._lookup("mkdir")

    @property
    def mkdirat(self) -> int:
        return self._lookup("mkdirat")

    @property
    def mknod(self) -> int:
        return self._lookup("mknod")

    @property
    def mknodat(self) -> int:
        return self._lookup("mknodat")

    @property
    def mlock(self) -> int:
        return self._lookup("mlock")

    @property
    def mlock2(self) -> int:
        return self._lookup("mlock2")

    @property
    def mlockall(self) -> int:
        return self._lookup("mlockall")

    @property
    def mmap(self) -> int:
        return self._lookup("mmap")

    @property
    def mmap2(self) -> int:
        return self._lookup("mmap2")

    @property
    def modify_ldt(self) -> int:
        return self._lookup("modify_ldt")

    @property
    def mount(self) -> int:
        return self._lookup("mount")

    @property
    def mount_setattr(self) -> int:
        return self._lookup("mount_setattr")

    @property
    def move_mount(self) -> int:
        return self._lookup("move_mount")

    @property
    def move_pages(self) -> int:
        return self._lookup("move_pages")

    @property
    def mprotect(self) -> int:
        return self._lookup("mprotect")

    @property
    def mq_getsetattr(self) -> int:
        return self._lookup("mq_getsetattr")

    @property
    def mq_notify(self) -> int:
        return self._lookup("mq_notify")

    @property
    def mq_open(self) -> int:
        return self._lookup("mq_open")

    @property
    def mq_timedreceive(self) -> int:
        return self._lookup("mq_timedreceive")

    @property
    def mq_timedreceive_time64(self) -> int:
        return self._lookup("mq_timedreceive_time64")

    @property
    def mq_timedsend(self) -> int:
        return self._lookup("mq_timedsend")

    @property
    def mq_timedsend_time64(self) -> int:
        return self._lookup("mq_timedsend_time64")

    @property
    def mq_unlink(self) -> int:
        return self._lookup("mq_unlink")

    @property
    def mremap(self) -> int:
        return self._lookup("mremap")

    @property
    def msgctl(self) -> int:
        return self._lookup("msgctl")

    @property
    def msgget(self) -> int:
        return self._lookup("msgget")

    @property
    def msgrcv(self) -> int:
        return self._lookup("msgrcv")

    @property
    def msgsnd(self) -> int:
        return self._lookup("msgsnd")

    @property
    def msync(self) -> int:
        return self._lookup("msync")

    @property
    def multiplexer(self) -> int:
        return self._lookup("multiplexer")

    @property
    def munlock(self) -> int:
        return self._lookup("munlock")

    @property
    def munlockall(self) -> int:
        return self._lookup("munlockall")

    @property
    def munmap(self) -> int:
        return self._lookup("munmap")

    @property
    def name_to_handle_at(self) -> int:
        return self._lookup("name_to_handle_at")

    @property
    def nanosleep(self) -> int:
        return self._lookup("nanosleep")

    @property
    def newfstatat(self) -> int:
        return self._lookup("newfstatat")

    @property
    def nfsservctl(self) -> int:
        return self._lookup("nfsservctl")

    @property
    def nice(self) -> int:
        return self._lookup("nice")

    @property
    def old_adjtimex(self) -> int:
        return self._lookup("old_adjtimex")

    @property
    def old_getpagesize(self) -> int:
        return self._lookup("old_getpagesize")

    @property
    def oldfstat(self) -> int:
        return self._lookup("oldfstat")

    @property
    def oldlstat(self) -> int:
        return self._lookup("oldlstat")

    @property
    def oldolduname(self) -> int:
        return self._lookup("oldolduname")

    @property
    def oldstat(self) -> int:
        return self._lookup("oldstat")

    @property
    def oldumount(self) -> int:
        return self._lookup("oldumount")

    @property
    def olduname(self) -> int:
        return self._lookup("olduname")

    @property
    def open(self) -> int:
        return self._lookup("open")

    @property
    def open_by_handle_at(self) -> int:
        return self._lookup("open_by_handle_at")

    @property
    def open_tree(self) -> int:
        return self._lookup("open_tree")

    @property
    def openat(self) -> int:
        return self._lookup("openat")

    @property
    def openat2(self) -> int:
        return self._lookup("openat2")

    @property
    def or1k_atomic(self) -> int:
        return self._lookup("or1k_atomic")

    @property
    def osf_adjtime(self) -> int:
        return self._lookup("osf_adjtime")

    @property
    def osf_afs_syscall(self) -> int:
        return self._lookup("osf_afs_syscall")

    @property
    def osf_alt_plock(self) -> int:
        return self._lookup("osf_alt_plock")

    @property
    def osf_alt_setsid(self) -> int:
        return self._lookup("osf_alt_setsid")

    @property
    def osf_alt_sigpending(self) -> int:
        return self._lookup("osf_alt_sigpending")

    @property
    def osf_asynch_daemon(self) -> int:
        return self._lookup("osf_asynch_daemon")

    @property
    def osf_audcntl(self) -> int:
        return self._lookup("osf_audcntl")

    @property
    def osf_audgen(self) -> int:
        return self._lookup("osf_audgen")

    @property
    def osf_chflags(self) -> int:
        return self._lookup("osf_chflags")

    @property
    def osf_execve(self) -> int:
        return self._lookup("osf_execve")

    @property
    def osf_exportfs(self) -> int:
        return self._lookup("osf_exportfs")

    @property
    def osf_fchflags(self) -> int:
        return self._lookup("osf_fchflags")

    @property
    def osf_fdatasync(self) -> int:
        return self._lookup("osf_fdatasync")

    @property
    def osf_fpathconf(self) -> int:
        return self._lookup("osf_fpathconf")

    @property
    def osf_fstat(self) -> int:
        return self._lookup("osf_fstat")

    @property
    def osf_fstatfs(self) -> int:
        return self._lookup("osf_fstatfs")

    @property
    def osf_fstatfs64(self) -> int:
        return self._lookup("osf_fstatfs64")

    @property
    def osf_fuser(self) -> int:
        return self._lookup("osf_fuser")

    @property
    def osf_getaddressconf(self) -> int:
        return self._lookup("osf_getaddressconf")

    @property
    def osf_getdirentries(self) -> int:
        return self._lookup("osf_getdirentries")

    @property
    def osf_getdomainname(self) -> int:
        return self._lookup("osf_getdomainname")

    @property
    def osf_getfh(self) -> int:
        return self._lookup("osf_getfh")

    @property
    def osf_getfsstat(self) -> int:
        return self._lookup("osf_getfsstat")

    @property
    def osf_gethostid(self) -> int:
        return self._lookup("osf_gethostid")

    @property
    def osf_getitimer(self) -> int:
        return self._lookup("osf_getitimer")

    @property
    def osf_getlogin(self) -> int:
        return self._lookup("osf_getlogin")

    @property
    def osf_getmnt(self) -> int:
        return self._lookup("osf_getmnt")

    @property
    def osf_getrusage(self) -> int:
        return self._lookup("osf_getrusage")

    @property
    def osf_getsysinfo(self) -> int:
        return self._lookup("osf_getsysinfo")

    @property
    def osf_gettimeofday(self) -> int:
        return self._lookup("osf_gettimeofday")

    @property
    def osf_kloadcall(self) -> int:
        return self._lookup("osf_kloadcall")

    @property
    def osf_kmodcall(self) -> int:
        return self._lookup("osf_kmodcall")

    @property
    def osf_lstat(self) -> int:
        return self._lookup("osf_lstat")

    @property
    def osf_memcntl(self) -> int:
        return self._lookup("osf_memcntl")

    @property
    def osf_mincore(self) -> int:
        return self._lookup("osf_mincore")

    @property
    def osf_mount(self) -> int:
        return self._lookup("osf_mount")

    @property
    def osf_mremap(self) -> int:
        return self._lookup("osf_mremap")

    @property
    def osf_msfs_syscall(self) -> int:
        return self._lookup("osf_msfs_syscall")

    @property
    def osf_msleep(self) -> int:
        return self._lookup("osf_msleep")

    @property
    def osf_mvalid(self) -> int:
        return self._lookup("osf_mvalid")

    @property
    def osf_mwakeup(self) -> int:
        return self._lookup("osf_mwakeup")

    @property
    def osf_naccept(self) -> int:
        return self._lookup("osf_naccept")

    @property
    def osf_nfssvc(self) -> int:
        return self._lookup("osf_nfssvc")

    @property
    def osf_ngetpeername(self) -> int:
        return self._lookup("osf_ngetpeername")

    @property
    def osf_ngetsockname(self) -> int:
        return self._lookup("osf_ngetsockname")

    @property
    def osf_nrecvfrom(self) -> int:
        return self._lookup("osf_nrecvfrom")

    @property
    def osf_nrecvmsg(self) -> int:
        return self._lookup("osf_nrecvmsg")

    @property
    def osf_nsendmsg(self) -> int:
        return self._lookup("osf_nsendmsg")

    @property
    def osf_ntp_adjtime(self) -> int:
        return self._lookup("osf_ntp_adjtime")

    @property
    def osf_ntp_gettime(self) -> int:
        return self._lookup("osf_ntp_gettime")

    @property
    def osf_old_creat(self) -> int:
        return self._lookup("osf_old_creat")

    @property
    def osf_old_fstat(self) -> int:
        return self._lookup("osf_old_fstat")

    @property
    def osf_old_getpgrp(self) -> int:
        return self._lookup("osf_old_getpgrp")

    @property
    def osf_old_killpg(self) -> int:
        return self._lookup("osf_old_killpg")

    @property
    def osf_old_lstat(self) -> int:
        return self._lookup("osf_old_lstat")

    @property
    def osf_old_open(self) -> int:
        return self._lookup("osf_old_open")

    @property
    def osf_old_sigaction(self) -> int:
        return self._lookup("osf_old_sigaction")

    @property
    def osf_old_sigblock(self) -> int:
        return self._lookup("osf_old_sigblock")

    @property
    def osf_old_sigreturn(self) -> int:
        return self._lookup("osf_old_sigreturn")

    @property
    def osf_old_sigsetmask(self) -> int:
        return self._lookup("osf_old_sigsetmask")

    @property
    def osf_old_sigvec(self) -> int:
        return self._lookup("osf_old_sigvec")

    @property
    def osf_old_stat(self) -> int:
        return self._lookup("osf_old_stat")

    @property
    def osf_old_vadvise(self) -> int:
        return self._lookup("osf_old_vadvise")

    @property
    def osf_old_vtrace(self) -> int:
        return self._lookup("osf_old_vtrace")

    @property
    def osf_old_wait(self) -> int:
        return self._lookup("osf_old_wait")

    @property
    def osf_oldquota(self) -> int:
        return self._lookup("osf_oldquota")

    @property
    def osf_pathconf(self) -> int:
        return self._lookup("osf_pathconf")

    @property
    def osf_pid_block(self) -> int:
        return self._lookup("osf_pid_block")

    @property
    def osf_pid_unblock(self) -> int:
        return self._lookup("osf_pid_unblock")

    @property
    def osf_plock(self) -> int:
        return self._lookup("osf_plock")

    @property
    def osf_priocntlset(self) -> int:
        return self._lookup("osf_priocntlset")

    @property
    def osf_profil(self) -> int:
        return self._lookup("osf_profil")

    @property
    def osf_proplist_syscall(self) -> int:
        return self._lookup("osf_proplist_syscall")

    @property
    def osf_reboot(self) -> int:
        return self._lookup("osf_reboot")

    @property
    def osf_revoke(self) -> int:
        return self._lookup("osf_revoke")

    @property
    def osf_sbrk(self) -> int:
        return self._lookup("osf_sbrk")

    @property
    def osf_security(self) -> int:
        return self._lookup("osf_security")

    @property
    def osf_select(self) -> int:
        return self._lookup("osf_select")

    @property
    def osf_set_program_attributes(self) -> int:
        return self._lookup("osf_set_program_attributes")

    @property
    def osf_set_speculative(self) -> int:
        return self._lookup("osf_set_speculative")

    @property
    def osf_sethostid(self) -> int:
        return self._lookup("osf_sethostid")

    @property
    def osf_setitimer(self) -> int:
        return self._lookup("osf_setitimer")

    @property
    def osf_setlogin(self) -> int:
        return self._lookup("osf_setlogin")

    @property
    def osf_setsysinfo(self) -> int:
        return self._lookup("osf_setsysinfo")

    @property
    def osf_settimeofday(self) -> int:
        return self._lookup("osf_settimeofday")

    @property
    def osf_shmat(self) -> int:
        return self._lookup("osf_shmat")

    @property
    def osf_signal(self) -> int:
        return self._lookup("osf_signal")

    @property
    def osf_sigprocmask(self) -> int:
        return self._lookup("osf_sigprocmask")

    @property
    def osf_sigsendset(self) -> int:
        return self._lookup("osf_sigsendset")

    @property
    def osf_sigstack(self) -> int:
        return self._lookup("osf_sigstack")

    @property
    def osf_sigwaitprim(self) -> int:
        return self._lookup("osf_sigwaitprim")

    @property
    def osf_sstk(self) -> int:
        return self._lookup("osf_sstk")

    @property
    def osf_stat(self) -> int:
        return self._lookup("osf_stat")

    @property
    def osf_statfs(self) -> int:
        return self._lookup("osf_statfs")

    @property
    def osf_statfs64(self) -> int:
        return self._lookup("osf_statfs64")

    @property
    def osf_subsys_info(self) -> int:
        return self._lookup("osf_subsys_info")

    @property
    def osf_swapctl(self) -> int:
        return self._lookup("osf_swapctl")

    @property
    def osf_swapon(self) -> int:
        return self._lookup("osf_swapon")

    @property
    def osf_syscall(self) -> int:
        return self._lookup("osf_syscall")

    @property
    def osf_sysinfo(self) -> int:
        return self._lookup("osf_sysinfo")

    @property
    def osf_table(self) -> int:
        return self._lookup("osf_table")

    @property
    def osf_uadmin(self) -> int:
        return self._lookup("osf_uadmin")

    @property
    def osf_usleep_thread(self) -> int:
        return self._lookup("osf_usleep_thread")

    @property
    def osf_uswitch(self) -> int:
        return self._lookup("osf_uswitch")

    @property
    def osf_utc_adjtime(self) -> int:
        return self._lookup("osf_utc_adjtime")

    @property
    def osf_utc_gettime(self) -> int:
        return self._lookup("osf_utc_gettime")

    @property
    def osf_utimes(self) -> int:
        return self._lookup("osf_utimes")

    @property
    def osf_utsname(self) -> int:
        return self._lookup("osf_utsname")

    @property
    def osf_wait4(self) -> int:
        return self._lookup("osf_wait4")

    @property
    def osf_waitid(self) -> int:
        return self._lookup("osf_waitid")

    @property
    def pause(self) -> int:
        return self._lookup("pause")

    @property
    def pciconfig_iobase(self) -> int:
        return self._lookup("pciconfig_iobase")

    @property
    def pciconfig_read(self) -> int:
        return self._lookup("pciconfig_read")

    @property
    def pciconfig_write(self) -> int:
        return self._lookup("pciconfig_write")

    @property
    def perf_event_open(self) -> int:
        return self._lookup("perf_event_open")

    @property
    def perfctr(self) -> int:
        return self._lookup("perfctr")

    @property
    def personality(self) -> int:
        return self._lookup("personality")

    @property
    def pidfd_getfd(self) -> int:
        return self._lookup("pidfd_getfd")

    @property
    def pidfd_open(self) -> int:
        return self._lookup("pidfd_open")

    @property
    def pidfd_send_signal(self) -> int:
        return self._lookup("pidfd_send_signal")

    @property
    def pipe(self) -> int:
        return self._lookup("pipe")

    @property
    def pipe2(self) -> int:
        return self._lookup("pipe2")

    @property
    def pivot_root(self) -> int:
        return self._lookup("pivot_root")

    @property
    def pkey_alloc(self) -> int:
        return self._lookup("pkey_alloc")

    @property
    def pkey_free(self) -> int:
        return self._lookup("pkey_free")

    @property
    def pkey_mprotect(self) -> int:
        return self._lookup("pkey_mprotect")

    @property
    def poll(self) -> int:
        return self._lookup("poll")

    @property
    def ppoll(self) -> int:
        return self._lookup("ppoll")

    @property
    def ppoll_time64(self) -> int:
        return self._lookup("ppoll_time64")

    @property
    def prctl(self) -> int:
        return self._lookup("prctl")

    @property
    def pread64(self) -> int:
        return self._lookup("pread64")

    @property
    def preadv(self) -> int:
        return self._lookup("preadv")

    @property
    def preadv2(self) -> int:
        return self._lookup("preadv2")

    @property
    def prlimit64(self) -> int:
        return self._lookup("prlimit64")

    @property
    def process_madvise(self) -> int:
        return self._lookup("process_madvise")

    @property
    def process_mrelease(self) -> int:
        return self._lookup("process_mrelease")

    @property
    def process_vm_readv(self) -> int:
        return self._lookup("process_vm_readv")

    @property
    def process_vm_writev(self) -> int:
        return self._lookup("process_vm_writev")

    @property
    def pselect6(self) -> int:
        return self._lookup("pselect6")

    @property
    def pselect6_time64(self) -> int:
        return self._lookup("pselect6_time64")

    @property
    def ptrace(self) -> int:
        return self._lookup("ptrace")

    @property
    def pwrite64(self) -> int:
        return self._lookup("pwrite64")

    @property
    def pwritev(self) -> int:
        return self._lookup("pwritev")

    @property
    def pwritev2(self) -> int:
        return self._lookup("pwritev2")

    @property
    def query_module(self) -> int:
        return self._lookup("query_module")

    @property
    def quotactl(self) -> int:
        return self._lookup("quotactl")

    @property
    def quotactl_fd(self) -> int:
        return self._lookup("quotactl_fd")

    @property
    def read(self) -> int:
        return self._lookup("read")

    @property
    def readahead(self) -> int:
        return self._lookup("readahead")

    @property
    def readdir(self) -> int:
        return self._lookup("readdir")

    @property
    def readlink(self) -> int:
        return self._lookup("readlink")

    @property
    def readlinkat(self) -> int:
        return self._lookup("readlinkat")

    @property
    def readv(self) -> int:
        return self._lookup("readv")

    @property
    def reboot(self) -> int:
        return self._lookup("reboot")

    @property
    def recv(self) -> int:
        return self._lookup("recv")

    @property
    def recvfrom(self) -> int:
        return self._lookup("recvfrom")

    @property
    def recvmmsg(self) -> int:
        return self._lookup("recvmmsg")

    @property
    def recvmmsg_time64(self) -> int:
        return self._lookup("recvmmsg_time64")

    @property
    def recvmsg(self) -> int:
        return self._lookup("recvmsg")

    @property
    def remap_file_pages(self) -> int:
        return self._lookup("remap_file_pages")

    @property
    def removexattr(self) -> int:
        return self._lookup("removexattr")

    @property
    def rename(self) -> int:
        return self._lookup("rename")

    @property
    def renameat(self) -> int:
        return self._lookup("renameat")

    @property
    def renameat2(self) -> int:
        return self._lookup("renameat2")

    @property
    def request_key(self) -> int:
        return self._lookup("request_key")

    @property
    def restart_syscall(self) -> int:
        return self._lookup("restart_syscall")

    @property
    def riscv_flush_icache(self) -> int:
        return self._lookup("riscv_flush_icache")

    @property
    def riscv_hwprobe(self) -> int:
        return self._lookup("riscv_hwprobe")

    @property
    def rmdir(self) -> int:
        return self._lookup("rmdir")

    @property
    def rseq(self) -> int:
        return self._lookup("rseq")

    @property
    def rt_sigaction(self) -> int:
        return self._lookup("rt_sigaction")

    @property
    def rt_sigpending(self) -> int:
        return self._lookup("rt_sigpending")

    @property
    def rt_sigprocmask(self) -> int:
        return self._lookup("rt_sigprocmask")

    @property
    def rt_sigqueueinfo(self) -> int:
        return self._lookup("rt_sigqueueinfo")

    @property
    def rt_sigreturn(self) -> int:
        return self._lookup("rt_sigreturn")

    @property
    def rt_sigsuspend(self) -> int:
        return self._lookup("rt_sigsuspend")

    @property
    def rt_sigtimedwait(self) -> int:
        return self._lookup("rt_sigtimedwait")

    @property
    def rt_sigtimedwait_time64(self) -> int:
        return self._lookup("rt_sigtimedwait_time64")

    @property
    def rt_tgsigqueueinfo(self) -> int:
        return self._lookup("rt_tgsigqueueinfo")

    @property
    def rtas(self) -> int:
        return self._lookup("rtas")

    @property
    def s390_guarded_storage(self) -> int:
        return self._lookup("s390_guarded_storage")

    @property
    def s390_pci_mmio_read(self) -> int:
        return self._lookup("s390_pci_mmio_read")

    @property
    def s390_pci_mmio_write(self) -> int:
        return self._lookup("s390_pci_mmio_write")

    @property
    def s390_runtime_instr(self) -> int:
        return self._lookup("s390_runtime_instr")

    @property
    def s390_sthyi(self) -> int:
        return self._lookup("s390_sthyi")

    @property
    def sched_get_affinity(self) -> int:
        return self._lookup("sched_get_affinity")

    @property
    def sched_get_priority_max(self) -> int:
        return self._lookup("sched_get_priority_max")

    @property
    def sched_get_priority_min(self) -> int:
        return self._lookup("sched_get_priority_min")

    @property
    def sched_getaffinity(self) -> int:
        return self._lookup("sched_getaffinity")

    @property
    def sched_getattr(self) -> int:
        return self._lookup("sched_getattr")

    @property
    def sched_getparam(self) -> int:
        return self._lookup("sched_getparam")

    @property
    def sched_getscheduler(self) -> int:
        return self._lookup("sched_getscheduler")

    @property
    def sched_rr_get_interval(self) -> int:
        return self._lookup("sched_rr_get_interval")

    @property
    def sched_rr_get_interval_time64(self) -> int:
        return self._lookup("sched_rr_get_interval_time64")

    @property
    def sched_set_affinity(self) -> int:
        return self._lookup("sched_set_affinity")

    @property
    def sched_setaffinity(self) -> int:
        return self._lookup("sched_setaffinity")

    @property
    def sched_setattr(self) -> int:
        return self._lookup("sched_setattr")

    @property
    def sched_setparam(self) -> int:
        return self._lookup("sched_setparam")

    @property
    def sched_setscheduler(self) -> int:
        return self._lookup("sched_setscheduler")

    @property
    def sched_yield(self) -> int:
        return self._lookup("sched_yield")

    @property
    def seccomp(self) -> int:
        return self._lookup("seccomp")

    @property
    def select(self) -> int:
        return self._lookup("select")

    @property
    def semctl(self) -> int:
        return self._lookup("semctl")

    @property
    def semget(self) -> int:
        return self._lookup("semget")

    @property
    def semop(self) -> int:
        return self._lookup("semop")

    @property
    def semtimedop(self) -> int:
        return self._lookup("semtimedop")

    @property
    def semtimedop_time64(self) -> int:
        return self._lookup("semtimedop_time64")

    @property
    def send(self) -> int:
        return self._lookup("send")

    @property
    def sendfile(self) -> int:
        return self._lookup("sendfile")

    @property
    def sendfile64(self) -> int:
        return self._lookup("sendfile64")

    @property
    def sendmmsg(self) -> int:
        return self._lookup("sendmmsg")

    @property
    def sendmsg(self) -> int:
        return self._lookup("sendmsg")

    @property
    def sendto(self) -> int:
        return self._lookup("sendto")

    @property
    def set_mempolicy(self) -> int:
        return self._lookup("set_mempolicy")

    @property
    def set_mempolicy_home_node(self) -> int:
        return self._lookup("set_mempolicy_home_node")

    @property
    def set_robust_list(self) -> int:
        return self._lookup("set_robust_list")

    @property
    def set_thread_area(self) -> int:
        return self._lookup("set_thread_area")

    @property
    def set_tid_address(self) -> int:
        return self._lookup("set_tid_address")

    @property
    def setdomainname(self) -> int:
        return self._lookup("setdomainname")

    @property
    def setfsgid(self) -> int:
        return self._lookup("setfsgid")

    @property
    def setfsgid32(self) -> int:
        return self._lookup("setfsgid32")

    @property
    def setfsuid(self) -> int:
        return self._lookup("setfsuid")

    @property
    def setfsuid32(self) -> int:
        return self._lookup("setfsuid32")

    @property
    def setgid(self) -> int:
        return self._lookup("setgid")

    @property
    def setgid32(self) -> int:
        return self._lookup("setgid32")

    @property
    def setgroups(self) -> int:
        return self._lookup("setgroups")

    @property
    def setgroups32(self) -> int:
        return self._lookup("setgroups32")

    @property
    def sethae(self) -> int:
        return self._lookup("sethae")

    @property
    def sethostname(self) -> int:
        return self._lookup("sethostname")

    @property
    def setitimer(self) -> int:
        return self._lookup("setitimer")

    @property
    def setns(self) -> int:
        return self._lookup("setns")

    @property
    def setpgid(self) -> int:
        return self._lookup("setpgid")

    @property
    def setpgrp(self) -> int:
        return self._lookup("setpgrp")

    @property
    def setpriority(self) -> int:
        return self._lookup("setpriority")

    @property
    def setregid(self) -> int:
        return self._lookup("setregid")

    @property
    def setregid32(self) -> int:
        return self._lookup("setregid32")

    @property
    def setresgid(self) -> int:
        return self._lookup("setresgid")

    @property
    def setresgid32(self) -> int:
        return self._lookup("setresgid32")

    @property
    def setresuid(self) -> int:
        return self._lookup("setresuid")

    @property
    def setresuid32(self) -> int:
        return self._lookup("setresuid32")

    @property
    def setreuid(self) -> int:
        return self._lookup("setreuid")

    @property
    def setreuid32(self) -> int:
        return self._lookup("setreuid32")

    @property
    def setrlimit(self) -> int:
        return self._lookup("setrlimit")

    @property
    def setsid(self) -> int:
        return self._lookup("setsid")

    @property
    def setsockopt(self) -> int:
        return self._lookup("setsockopt")

    @property
    def settimeofday(self) -> int:
        return self._lookup("settimeofday")

    @property
    def setuid(self) -> int:
        return self._lookup("setuid")

    @property
    def setuid32(self) -> int:
        return self._lookup("setuid32")

    @property
    def setxattr(self) -> int:
        return self._lookup("setxattr")

    @property
    def sgetmask(self) -> int:
        return self._lookup("sgetmask")

    @property
    def shmat(self) -> int:
        return self._lookup("shmat")

    @property
    def shmctl(self) -> int:
        return self._lookup("shmctl")

    @property
    def shmdt(self) -> int:
        return self._lookup("shmdt")

    @property
    def shmget(self) -> int:
        return self._lookup("shmget")

    @property
    def shutdown(self) -> int:
        return self._lookup("shutdown")

    @property
    def sigaction(self) -> int:
        return self._lookup("sigaction")

    @property
    def sigaltstack(self) -> int:
        return self._lookup("sigaltstack")

    @property
    def signal(self) -> int:
        return self._lookup("signal")

    @property
    def signalfd(self) -> int:
        return self._lookup("signalfd")

    @property
    def signalfd4(self) -> int:
        return self._lookup("signalfd4")

    @property
    def sigpending(self) -> int:
        return self._lookup("sigpending")

    @property
    def sigprocmask(self) -> int:
        return self._lookup("sigprocmask")

    @property
    def sigreturn(self) -> int:
        return self._lookup("sigreturn")

    @property
    def sigsuspend(self) -> int:
        return self._lookup("sigsuspend")

    @property
    def socket(self) -> int:
        return self._lookup("socket")

    @property
    def socketcall(self) -> int:
        return self._lookup("socketcall")

    @property
    def socketpair(self) -> int:
        return self._lookup("socketpair")

    @property
    def splice(self) -> int:
        return self._lookup("splice")

    @property
    def spu_create(self) -> int:
        return self._lookup("spu_create")

    @property
    def spu_run(self) -> int:
        return self._lookup("spu_run")

    @property
    def ssetmask(self) -> int:
        return self._lookup("ssetmask")

    @property
    def stat(self) -> int:
        return self._lookup("stat")

    @property
    def stat64(self) -> int:
        return self._lookup("stat64")

    @property
    def statfs(self) -> int:
        return self._lookup("statfs")

    @property
    def statfs64(self) -> int:
        return self._lookup("statfs64")

    @property
    def statx(self) -> int:
        return self._lookup("statx")

    @property
    def stime(self) -> int:
        return self._lookup("stime")

    @property
    def subpage_prot(self) -> int:
        return self._lookup("subpage_prot")

    @property
    def swapcontext(self) -> int:
        return self._lookup("swapcontext")

    @property
    def swapoff(self) -> int:
        return self._lookup("swapoff")

    @property
    def swapon(self) -> int:
        return self._lookup("swapon")

    @property
    def switch_endian(self) -> int:
        return self._lookup("switch_endian")

    @property
    def symlink(self) -> int:
        return self._lookup("symlink")

    @property
    def symlinkat(self) -> int:
        return self._lookup("symlinkat")

    @property
    def sync(self) -> int:
        return self._lookup("sync")

    @property
    def sync_file_range(self) -> int:
        return self._lookup("sync_file_range")

    @property
    def sync_file_range2(self) -> int:
        return self._lookup("sync_file_range2")

    @property
    def syncfs(self) -> int:
        return self._lookup("syncfs")

    @property
    def sys_debug_setcontext(self) -> int:
        return self._lookup("sys_debug_setcontext")

    @property
    def syscall(self) -> int:
        return self._lookup("syscall")

    @property
    def sysfs(self) -> int:
        return self._lookup("sysfs")

    @property
    def sysinfo(self) -> int:
        return self._lookup("sysinfo")

    @property
    def syslog(self) -> int:
        return self._lookup("syslog")

    @property
    def sysmips(self) -> int:
        return self._lookup("sysmips")

    @property
    def tee(self) -> int:
        return self._lookup("tee")

    @property
    def tgkill(self) -> int:
        return self._lookup("tgkill")

    @property
    def time(self) -> int:
        return self._lookup("time")

    @property
    def timer_create(self) -> int:
        return self._lookup("timer_create")

    @property
    def timer_delete(self) -> int:
        return self._lookup("timer_delete")

    @property
    def timer_getoverrun(self) -> int:
        return self._lookup("timer_getoverrun")

    @property
    def timer_gettime(self) -> int:
        return self._lookup("timer_gettime")

    @property
    def timer_gettime64(self) -> int:
        return self._lookup("timer_gettime64")

    @property
    def timer_settime(self) -> int:
        return self._lookup("timer_settime")

    @property
    def timer_settime64(self) -> int:
        return self._lookup("timer_settime64")

    @property
    def timerfd(self) -> int:
        return self._lookup("timerfd")

    @property
    def timerfd_create(self) -> int:
        return self._lookup("timerfd_create")

    @property
    def timerfd_gettime(self) -> int:
        return self._lookup("timerfd_gettime")

    @property
    def timerfd_gettime64(self) -> int:
        return self._lookup("timerfd_gettime64")

    @property
    def timerfd_settime(self) -> int:
        return self._lookup("timerfd_settime")

    @property
    def timerfd_settime64(self) -> int:
        return self._lookup("timerfd_settime64")

    @property
    def times(self) -> int:
        return self._lookup("times")

    @property
    def tkill(self) -> int:
        return self._lookup("tkill")

    @property
    def truncate(self) -> int:
        return self._lookup("truncate")

    @property
    def truncate64(self) -> int:
        return self._lookup("truncate64")

    @property
    def ugetrlimit(self) -> int:
        return self._lookup("ugetrlimit")

    @property
    def umask(self) -> int:
        return self._lookup("umask")

    @property
    def umount(self) -> int:
        return self._lookup("umount")

    @property
    def umount2(self) -> int:
        return self._lookup("umount2")

    @property
    def uname(self) -> int:
        return self._lookup("uname")

    @property
    def unlink(self) -> int:
        return self._lookup("unlink")

    @property
    def unlinkat(self) -> int:
        return self._lookup("unlinkat")

    @property
    def unshare(self) -> int:
        return self._lookup("unshare")

    @property
    def uselib(self) -> int:
        return self._lookup("uselib")

    @property
    def userfaultfd(self) -> int:
        return self._lookup("userfaultfd")

    @property
    def ustat(self) -> int:
        return self._lookup("ustat")

    @property
    def utime(self) -> int:
        return self._lookup("utime")

    @property
    def utimensat(self) -> int:
        return self._lookup("utimensat")

    @property
    def utimensat_time64(self) -> int:
        return self._lookup("utimensat_time64")

    @property
    def utimes(self) -> int:
        return self._lookup("utimes")

    @property
    def utrap_install(self) -> int:
        return self._lookup("utrap_install")

    @property
    def vfork(self) -> int:
        return self._lookup("vfork")

    @property
    def vhangup(self) -> int:
        return self._lookup("vhangup")

    @property
    def vm86(self) -> int:
        return self._lookup("vm86")

    @property
    def vm86old(self) -> int:
        return self._lookup("vm86old")

    @property
    def vmsplice(self) -> int:
        return self._lookup("vmsplice")

    @property
    def wait4(self) -> int:
        return self._lookup("wait4")

    @property
    def waitid(self) -> int:
        return self._lookup("waitid")

    @property
    def waitpid(self) -> int:
        return self._lookup("waitpid")

    @property
    def write(self) -> int:
        return self._lookup("write")

    @property
    def writev(self) -> int:
        return self._lookup("writev")
