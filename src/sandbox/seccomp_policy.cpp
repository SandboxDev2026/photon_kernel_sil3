// LightPool seccomp-BPF 双模式策略实现
#include <sys/syscall.h>
#include "photon_kernel/sandbox/seccomp_policy.hpp"

// x86_64 syscall 号补充定义（某些系统 <sys/syscall.h> 可能缺少这些）
#ifndef SYS_get_robust_list
#define SYS_get_robust_list 274
#endif
#ifndef SYS_set_robust_list
#define SYS_set_robust_list 273
#endif
#ifndef SYS_inotify_read
#define SYS_inotify_read 0  // inotify 不通过专门 syscall 读取，用 read()
#endif
#ifndef SYS_pread
#define SYS_pread 17  // x86_64 上实际是 pread64=17
#endif
#ifndef SYS_pwrite
#define SYS_pwrite 18  // x86_64 上实际是 pwrite64=18
#endif
#ifndef SYS_getdents
#define SYS_getdents 78  // x86_64 上实际是 getdents64=217
#endif
#ifndef SYS_umount
#define SYS_umount 166  // x86_64 上是 umount2=166
#endif
#ifndef SYS_wait
#define SYS_wait 61  // x86_64 上没有 wait，只有 wait4=61
#endif
#ifndef SYS_pselect
#define SYS_pselect 72  // x86_64 上是 pselect6=72
#endif
#ifndef SYS_fadvise
#define SYS_fadvise 221  // x86_64 上是 fadvise64=221
#endif
#ifndef SYS_signalfd
#define SYS_signalfd 282  // x86_64 上是 signalfd4=282
#endif
#ifndef SYS_dup
#define SYS_dup 32
#endif
#ifndef SYS_dup2
#define SYS_dup2 33
#endif
#ifndef SYS_dup3
#define SYS_dup3 292
#endif
#ifndef SYS_pipe
#define SYS_pipe 22
#endif
#ifndef SYS_eventfd
#define SYS_eventfd 284
#endif
#ifndef SYS_epoll_create
#define SYS_epoll_create 213
#endif
#ifndef SYS_inotify_init
#define SYS_inotify_init 253
#endif
#ifndef SYS_faccessat
#define SYS_faccessat 269
#endif
#ifndef SYS_newfstatat
#define SYS_newfstatat 262
#endif
#ifndef SYS_unlinkat
#define SYS_unlinkat 263
#endif
#ifndef SYS_mkdirat
#define SYS_mkdirat 258
#endif
#ifndef SYS_fchmodat
#define SYS_fchmodat 268
#endif
#ifndef SYS_fchownat
#define SYS_fchownat 260
#endif
#ifndef SYS_readlinkat
#define SYS_readlinkat 267
#endif
#ifndef SYS_symlinkat
#define SYS_symlinkat 266
#endif
#ifndef SYS_linkat
#define SYS_linkat 265
#endif
#ifndef SYS_renameat
#define SYS_renameat 264
#endif
#ifndef SYS_utimensat
#define SYS_utimensat 280
#endif
#ifndef SYS_copy_file_range
#define SYS_copy_file_range 326
#endif
#ifndef SYS_preadv
#define SYS_preadv 295
#endif
#ifndef SYS_pwritev
#define SYS_pwritev 296
#endif
#ifndef SYS_statx
#define SYS_statx 332
#endif
#ifndef SYS_memfd_create
#define SYS_memfd_create 319
#endif
#ifndef SYS_userfaultfd
#define SYS_userfaultfd 323
#endif
#ifndef SYS_rseq
#define SYS_rseq 334
#endif
#ifndef SYS_bpf
#define SYS_bpf 321
#endif
#ifndef SYS_seccomp
#define SYS_seccomp 317
#endif
#ifndef SYS_getcpu
#define SYS_getcpu 309
#endif
#ifndef SYS_perf_event_open
#define SYS_perf_event_open 298
#endif
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_clone3
#define SYS_clone3 435
#endif
#ifndef SYS_process_madvise
#define SYS_process_madvise 440
#endif
#ifndef SYS_epoll_pwait2
#define SYS_epoll_pwait2 441
#endif
#ifndef SYS_faccessat2
#define SYS_faccessat2 439
#endif
#ifndef SYS_landlock_create_ruleset
#define SYS_landlock_create_ruleset 444
#endif
#ifndef SYS_landlock_add_rule
#define SYS_landlock_add_rule 445
#endif
#ifndef SYS_landlock_restrict_self
#define SYS_landlock_restrict_self 446
#endif
#ifndef SYS_open_by_handle_at
#define SYS_open_by_handle_at 304
#endif
#ifndef SYS_init_module
#define SYS_init_module 322
#endif
#ifndef SYS_finit_module
#define SYS_finit_module 323
#endif
#ifndef SYS_kexec_load
#define SYS_kexec_load 246
#endif
#ifndef SYS_ptrace
#define SYS_ptrace 101
#endif
#ifndef SYS_mount
#define SYS_mount 165
#endif
#ifndef SYS_umount2
#define SYS_umount2 166
#endif
#ifndef SYS_swapon
#define SYS_swapon 167
#endif
#ifndef SYS_swapoff
#define SYS_swapoff 168
#endif
#ifndef SYS_reboot
#define SYS_reboot 169
#endif
#ifndef SYS_ioperm
#define SYS_ioperm 173
#endif
#ifndef SYS_iopl
#define SYS_iopl 172
#endif
#ifndef SYS_pivot_root
#define SYS_pivot_root 155
#endif
#ifndef SYS_personality
#define SYS_personality 135
#endif
#ifndef SYS_unshare
#define SYS_unshare 272
#endif
#ifndef SYS_setns
#define SYS_setns 308
#endif
#ifndef SYS_keyctl
#define SYS_keyctl 250
#endif
#ifndef SYS_add_key
#define SYS_add_key 248
#endif
#ifndef SYS_request_key
#define SYS_request_key 249
#endif
#ifndef SYS_futex
#define SYS_futex 202
#endif
#ifndef SYS_inotify_rm_watch
#define SYS_inotify_rm_watch 255
#endif
#ifndef SYS_inotify_add_watch
#define SYS_inotify_add_watch 254
#endif
#ifndef SYS_sigaction
#define SYS_sigaction 13
#endif
#ifndef SYS_sigprocmask
#define SYS_sigprocmask 14
#endif
#ifndef SYS_sigreturn
#define SYS_sigreturn 15
#endif
#ifndef SYS_execveat
#define SYS_execveat 322
#endif


#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <ctime>
#include <openssl/sha.h>

// x86_64 syscall 号（仅列出关键的，完整列表使用 <sys/syscall.h>）
#ifndef SYS_ptrace
#define SYS_ptrace 101
#endif
#ifndef SYS_kexec_load
#define SYS_kexec_load 246
#endif
#ifndef SYS_mount
#define SYS_mount 165
#endif
#ifndef SYS_umount2
#define SYS_umount2 166
#endif
#ifndef SYS_open_by_handle_at
#define SYS_open_by_handle_at 304
#endif
#ifndef SYS_init_module
#define SYS_init_module 322
#endif
#ifndef SYS_finit_module
#define SYS_finit_module 323
#endif
#ifndef SYS_clone
#define SYS_clone 56
#endif
#ifndef SYS_openat
#define SYS_openat 257
#endif
#ifndef SYS_execve
#define SYS_execve 59
#endif
#ifndef SYS_futex
#define SYS_futex 202
#endif
#ifndef SYS_inotify_rm_watch
#define SYS_inotify_rm_watch 255
#endif
#ifndef SYS_inotify_add_watch
#define SYS_inotify_add_watch 254
#endif
#ifndef SYS_sigaction
#define SYS_sigaction 13
#endif
#ifndef SYS_sigprocmask
#define SYS_sigprocmask 14
#endif
#ifndef SYS_sigreturn
#define SYS_sigreturn 15
#endif
#ifndef SYS_execveat
#define SYS_execveat 322
#endif
#ifndef SYS_swapon
#define SYS_swapon 167
#endif
#ifndef SYS_swapoff
#define SYS_swapoff 168
#endif
#ifndef SYS_reboot
#define SYS_reboot 169
#endif
#ifndef SYS_ioperm
#define SYS_ioperm 173
#endif
#ifndef SYS_iopl
#define SYS_iopl 172
#endif
#ifndef SYS_pivot_root
#define SYS_pivot_root 155
#endif
#ifndef SYS_personality
#define SYS_personality 135
#endif
#ifndef SYS_unshare
#define SYS_unshare 272
#endif
#ifndef SYS_setns
#define SYS_setns 308
#endif
#ifndef SYS_keyctl
#define SYS_keyctl 250
#endif
#ifndef SYS_add_key
#define SYS_add_key 248
#endif
#ifndef SYS_clone3
#define SYS_clone3 435
#endif
#ifndef SYS_request_key
#define SYS_request_key 249
#endif
#ifndef SYS_perf_event_open
#define SYS_perf_event_open 298
#endif
#ifndef SYS_landlock_create_ruleset
#define SYS_landlock_create_ruleset 444
#endif
#ifndef SYS_landlock_add_rule
#define SYS_landlock_add_rule 445
#endif
#ifndef SYS_landlock_restrict_self
#define SYS_landlock_restrict_self 446
#endif
#ifndef SYS_rseq
#define SYS_rseq 334
#endif
#ifndef SYS_userfaultfd
#define SYS_userfaultfd 323
#endif
#ifndef SYS_statx
#define SYS_statx 332
#endif
#ifndef SYS_copy_file_range
#define SYS_copy_file_range 326
#endif
#ifndef SYS_preadv2
#define SYS_preadv2 327
#endif
#ifndef SYS_pwritev2
#define SYS_pwritev2 328
#endif
#ifndef SYS_process_madvise
#define SYS_process_madvise 440
#endif
#ifndef SYS_epoll_pwait2
#define SYS_epoll_pwait2 441
#endif
#ifndef SYS_memfd_create
#define SYS_memfd_create 319
#endif
#ifndef SYS_bpf
#define SYS_bpf 321
#endif
#ifndef SYS_seccomp
#define SYS_seccomp 317
#endif
#ifndef SYS_getcpu
#define SYS_getcpu 309
#endif
#ifndef SYS_faccessat2
#define SYS_faccessat2 439
#endif
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_clone3
#define SYS_clone3 435
#endif

// clone flag
#ifndef CLONE_NEWNS
#define CLONE_NEWNS 0x00020000
#endif
#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER 0x10000000
#endif
#ifndef CLONE_NEWPID
#define CLONE_NEWPID 0x20000000
#endif
#ifndef CLONE_NEWNET
#define CLONE_NEWNET 0x40000000
#endif

// openat flag
#ifndef O_WRONLY
#define O_WRONLY 01
#endif
#ifndef O_RDWR
#define O_RDWR 02
#endif

namespace photon_kernel {
namespace sandbox {

uint64_t SeccompPolicy::violation_count_ = 0;

SeccompPolicy::SeccompPolicy(SeccompMode mode) : mode_(mode) {
    add_common_allowed();
    add_dangerous_syscalls();
    add_param_filters();

    if (mode_ == SeccompMode::DEFAULT) {
        init_default_mode();
    } else {
        init_untrusted_mode();
    }
}

std::string SeccompPolicy::mode_name() const {
    switch (mode_) {
        case SeccompMode::DEFAULT: return "default_mode";
        case SeccompMode::UNTRUSTED_CODE: return "untrusted_code_mode";
    }
    return "unknown";
}

void SeccompPolicy::add_common_allowed() {
    // 基础文件操作
    allowed_.insert(SYS_read);
    allowed_.insert(SYS_write);
    allowed_.insert(SYS_readv);
    allowed_.insert(SYS_writev);
    allowed_.insert(SYS_pread64);
    allowed_.insert(SYS_pwrite64);
    allowed_.insert(SYS_openat);
    allowed_.insert(SYS_close);
    allowed_.insert(SYS_stat);
    allowed_.insert(SYS_fstat);
    allowed_.insert(SYS_lstat);
    allowed_.insert(SYS_newfstatat);
    allowed_.insert(SYS_lseek);
    allowed_.insert(SYS_dup);
    allowed_.insert(SYS_dup2);
    allowed_.insert(SYS_dup3);
    allowed_.insert(SYS_fcntl);
    allowed_.insert(SYS_flock);
    allowed_.insert(SYS_fsync);
    allowed_.insert(SYS_fdatasync);
    allowed_.insert(SYS_truncate);
    allowed_.insert(SYS_ftruncate);
    allowed_.insert(SYS_getdents64);
    allowed_.insert(SYS_access);
    allowed_.insert(SYS_faccessat);
    allowed_.insert(SYS_faccessat2);
    allowed_.insert(SYS_pipe);
    allowed_.insert(SYS_pipe2);
    allowed_.insert(SYS_tee);
    allowed_.insert(SYS_splice);
    allowed_.insert(SYS_vmsplice);

    // 进程管理
    allowed_.insert(SYS_clone);
    allowed_.insert(SYS_clone3);
    allowed_.insert(SYS_fork);
    allowed_.insert(SYS_vfork);
    allowed_.insert(SYS_execve);
    allowed_.insert(SYS_execveat);
    allowed_.insert(SYS_exit);
    allowed_.insert(SYS_exit_group);
    allowed_.insert(SYS_wait4);
    allowed_.insert(SYS_waitid);
    allowed_.insert(SYS_getpid);
    allowed_.insert(SYS_getppid);
    allowed_.insert(SYS_gettid);
    allowed_.insert(SYS_sched_yield);
    allowed_.insert(SYS_sched_getaffinity);
    allowed_.insert(SYS_sched_setaffinity);
    allowed_.insert(SYS_sched_getscheduler);
    allowed_.insert(SYS_sched_setscheduler);
    allowed_.insert(SYS_sched_getparam);
    allowed_.insert(SYS_sched_setparam);
    allowed_.insert(SYS_prctl);
    allowed_.insert(SYS_arch_prctl);

    // 内存管理
    allowed_.insert(SYS_mmap);
    allowed_.insert(SYS_munmap);
    allowed_.insert(SYS_mprotect);
    allowed_.insert(SYS_brk);
    allowed_.insert(SYS_mremap);
    allowed_.insert(SYS_msync);
    allowed_.insert(SYS_mlock);
    allowed_.insert(SYS_munlock);
    allowed_.insert(SYS_mlockall);
    allowed_.insert(SYS_munlockall);
    allowed_.insert(SYS_mincore);
    allowed_.insert(SYS_madvise);
    allowed_.insert(SYS_process_madvise);

    // 信号
    allowed_.insert(SYS_sigaction);
    allowed_.insert(SYS_sigprocmask);
    allowed_.insert(SYS_sigreturn);
    allowed_.insert(SYS_sigaltstack);
    allowed_.insert(SYS_kill);
    allowed_.insert(SYS_tkill);
    allowed_.insert(SYS_tgkill);
    allowed_.insert(SYS_signalfd);
    allowed_.insert(SYS_signalfd4);
    allowed_.insert(SYS_timer_create);
    allowed_.insert(SYS_timer_settime);
    allowed_.insert(SYS_timer_gettime);
    allowed_.insert(SYS_timer_getoverrun);
    allowed_.insert(SYS_timer_delete);
    allowed_.insert(SYS_setitimer);
    allowed_.insert(SYS_getitimer);
    allowed_.insert(SYS_clock_gettime);
    allowed_.insert(SYS_clock_settime);
    allowed_.insert(SYS_clock_getres);
    allowed_.insert(SYS_clock_nanosleep);
    allowed_.insert(SYS_nanosleep);
    allowed_.insert(SYS_gettimeofday);
    allowed_.insert(SYS_settimeofday);
    allowed_.insert(SYS_time);

    // 网络（基础）
    allowed_.insert(SYS_socket);
    allowed_.insert(SYS_connect);
    allowed_.insert(SYS_accept);
    allowed_.insert(SYS_accept4);
    allowed_.insert(SYS_sendto);
    allowed_.insert(SYS_recvfrom);
    allowed_.insert(SYS_sendmsg);
    allowed_.insert(SYS_recvmsg);
    allowed_.insert(SYS_shutdown);
    allowed_.insert(SYS_bind);
    allowed_.insert(SYS_listen);
    allowed_.insert(SYS_getsockname);
    allowed_.insert(SYS_getpeername);
    allowed_.insert(SYS_setsockopt);
    allowed_.insert(SYS_getsockopt);
    allowed_.insert(SYS_socketpair);

    // 系统信息
    allowed_.insert(SYS_uname);
    allowed_.insert(SYS_sysinfo);
    allowed_.insert(SYS_getrandom);
    allowed_.insert(SYS_getuid);
    allowed_.insert(SYS_geteuid);
    allowed_.insert(SYS_getgid);
    allowed_.insert(SYS_getegid);
    allowed_.insert(SYS_getgroups);
    allowed_.insert(SYS_setgroups);
    allowed_.insert(SYS_getresuid);
    allowed_.insert(SYS_setresuid);
    allowed_.insert(SYS_getresgid);
    allowed_.insert(SYS_setresgid);
    allowed_.insert(SYS_capget);
    allowed_.insert(SYS_capset);

    // IPC
    allowed_.insert(SYS_preadv);
    allowed_.insert(SYS_pwritev);
    allowed_.insert(SYS_preadv2);
    allowed_.insert(SYS_pwritev2);

    // 其他常用
    allowed_.insert(SYS_ioctl);
    allowed_.insert(SYS_fadvise64);
    allowed_.insert(SYS_fallocate);
    allowed_.insert(SYS_renameat);
    allowed_.insert(SYS_renameat2);
    allowed_.insert(SYS_linkat);
    allowed_.insert(SYS_unlinkat);
    allowed_.insert(SYS_mkdirat);
    allowed_.insert(SYS_symlinkat);
    allowed_.insert(SYS_readlinkat);
    allowed_.insert(SYS_fchmodat);
    allowed_.insert(SYS_fchownat);
    allowed_.insert(SYS_utimensat);
    allowed_.insert(SYS_copy_file_range);
    allowed_.insert(SYS_statx);
    allowed_.insert(SYS_memfd_create);
    allowed_.insert(SYS_userfaultfd);
    allowed_.insert(SYS_rseq);
    allowed_.insert(SYS_landlock_create_ruleset);
    allowed_.insert(SYS_landlock_add_rule);
    allowed_.insert(SYS_landlock_restrict_self);
    allowed_.insert(SYS_seccomp);
    allowed_.insert(SYS_getcpu);
    allowed_.insert(SYS_epoll_create);
    allowed_.insert(SYS_epoll_create1);
    allowed_.insert(SYS_epoll_ctl);
    allowed_.insert(SYS_epoll_wait);
    allowed_.insert(SYS_epoll_pwait);
    allowed_.insert(SYS_epoll_pwait2);
    allowed_.insert(SYS_eventfd);
    allowed_.insert(SYS_eventfd2);
    allowed_.insert(SYS_poll);
    allowed_.insert(SYS_ppoll);
    allowed_.insert(SYS_select);
    allowed_.insert(SYS_pselect6);
    allowed_.insert(SYS_inotify_init);
    allowed_.insert(SYS_inotify_init1);
    allowed_.insert(SYS_inotify_add_watch);
    allowed_.insert(SYS_inotify_rm_watch);
    allowed_.insert(SYS_inotify_read);
    allowed_.insert(SYS_futex);
    allowed_.insert(SYS_set_robust_list);
    allowed_.insert(SYS_get_robust_list);
    allowed_.insert(SYS_bpf);
    allowed_.insert(SYS_perf_event_open);
}

void SeccompPolicy::add_dangerous_syscalls() {
    dangerous_ = {
        {SYS_ptrace, "ptrace", "进程注入/调试，可用于逃逸", true},
        {SYS_kexec_load, "kexec_load", "加载新内核，直接接管宿主", false},
        {SYS_mount, "mount", "挂载文件系统，可逃逸到宿主", true},
        {SYS_umount2, "umount2", "卸载文件系统", false},
        {SYS_open_by_handle_at, "open_by_handle_at", "通过文件句柄绕过路径检查", false},
        {SYS_init_module, "init_module", "加载内核模块，直接获得内核权限", false},
        {SYS_finit_module, "finit_module", "从fd加载内核模块", false},
    };
}

void SeccompPolicy::add_param_filters() {
    // clone: 禁止 CLONE_NEWNS / CLONE_NEWUSER / CLONE_NEWPID / CLONE_NEWNET
    // 阻止沙盒内新建命名空间逃逸
    uint64_t ns_flags = CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET;
    ParamFilterRule clone_filter;
    clone_filter.syscall_nr = SYS_clone;
    clone_filter.arg_index = 0;
    clone_filter.mask = ns_flags;
    clone_filter.value = ns_flags;
    clone_filter.description = "clone: 禁止 CLONE_NEWNS|CLONE_NEWUSER|CLONE_NEWPID|CLONE_NEWNET（阻止沙盒内新建命名空间）";
    param_filters_.push_back(clone_filter);

    // clone3 同样过滤（flags 在 clone_args 结构中，BPF 可读取）
    ParamFilterRule clone3_filter;
    clone3_filter.syscall_nr = SYS_clone3;
    clone3_filter.arg_index = 0;
    clone3_filter.mask = ns_flags;
    clone3_filter.value = ns_flags;
    clone3_filter.description = "clone3: 禁止 namespace 相关 flag";
    param_filters_.push_back(clone3_filter);

    // openat: 拒绝 O_WRONLY | O_RDWR 访问敏感路径
    // 注意：路径过滤需要 eBPF 配合，seccomp BPF 只能检查 flag
    // 这里标记需要参数过滤，实际路径检查由 eBPF/Landlock 完成
    ParamFilterRule openat_filter;
    openat_filter.syscall_nr = SYS_openat;
    openat_filter.arg_index = 1;
    openat_filter.mask = O_WRONLY | O_RDWR;
    openat_filter.value = O_WRONLY | O_RDWR;
    openat_filter.description = "openat: 标记写访问，配合 eBPF/Landlock 检查敏感路径（/proc/kcore, /dev/mem 等）";
    param_filters_.push_back(openat_filter);
}

void SeccompPolicy::init_default_mode() {
    // default_mode: 常规业务，在 common 基础上允许更多
    // 允许 ptrace（业务可能需要调试子进程）
    allowed_.insert(SYS_ptrace);
    // 允许 mount（业务可能需要 tmpfs 等）
    allowed_.insert(SYS_mount);
    allowed_.insert(SYS_umount2);
    // 允许 keyctl（某些业务需要）
    allowed_.insert(SYS_keyctl);
    allowed_.insert(SYS_add_key);
    allowed_.insert(SYS_request_key);
    // 允许 unshare（业务可能需要隔离）
    allowed_.insert(SYS_unshare);
    allowed_.insert(SYS_setns);
}

void SeccompPolicy::init_untrusted_mode() {
    // untrusted_code_mode: 严格最小权限，从白名单中移除高危 syscall
    for (const auto& ds : dangerous_) {
        allowed_.erase(ds.nr);
    }
    // 额外禁用：unshare/setns（防止新建 namespace）
    allowed_.erase(SYS_unshare);
    allowed_.erase(SYS_setns);
    // 禁用 keyctl（防止密钥操作）
    allowed_.erase(SYS_keyctl);
    allowed_.erase(SYS_add_key);
    allowed_.erase(SYS_request_key);
    // 禁用 personality（防止 32 位兼容模式绕过）
    allowed_.erase(SYS_personality);
    // 禁用 pivot_root
    allowed_.erase(SYS_pivot_root);
    // 禁用 swapon/swapoff
    allowed_.erase(SYS_swapon);
    allowed_.erase(SYS_swapoff);
    // 禁用 reboot
    allowed_.erase(SYS_reboot);
    // 禁用 ioperm/iopl
    allowed_.insert(SYS_ioperm); // 先确保存在再删除
    allowed_.erase(SYS_ioperm);
    allowed_.erase(SYS_iopl);
}

bool SeccompPolicy::is_allowed(int syscall_nr) const {
    return allowed_.count(syscall_nr) > 0;
}

bool SeccompPolicy::has_param_filter(int syscall_nr) const {
    for (const auto& pf : param_filters_) {
        if (pf.syscall_nr == syscall_nr) return true;
    }
    return false;
}

std::string SeccompPolicy::generate_bpf_program() const {
    std::ostringstream oss;
    oss << "# seccomp BPF program generated by PhotonBox SeccompPolicy\n";
    oss << "# mode: " << mode_name() << "\n";
    oss << "# allowed syscalls: " << allowed_.size() << "\n";
    oss << "# dangerous syscalls: " << dangerous_.size() << "\n";
    oss << "# param filters: " << param_filters_.size() << "\n";
    oss << "# default action: SECCOMP_RET_KILL_PROCESS\n\n";

    oss << "# 高危 syscall（直接 KILL）:\n";
    for (const auto& ds : dangerous_) {
        if (!is_allowed(ds.nr)) {
            oss << "#   " << ds.name << " (nr=" << ds.nr << "): " << ds.reason << "\n";
        }
    }

    oss << "\n# 参数过滤规则:\n";
    for (const auto& pf : param_filters_) {
        oss << "#   syscall=" << pf.syscall_nr
            << " arg[" << pf.arg_index << "]"
            << " mask=0x" << std::hex << pf.mask
            << " value=0x" << pf.value << std::dec
            << ": " << pf.description << "\n";
    }

    oss << "\n# BPF 伪代码（实际由 libseccomp 编译）:\n";
    oss << "if (syscall_nr in allowed_set) {\n";
    oss << "  if (has_param_filter(syscall_nr)) {\n";
    oss << "    if (param_matches_filter) return SECCOMP_RET_KILL_PROCESS;\n";
    oss << "  }\n";
    oss << "  return SECCOMP_RET_ALLOW;\n";
    oss << "}\n";
    oss << "log_violation();\n";
    oss << "return SECCOMP_RET_KILL_PROCESS;\n";

    return oss.str();
}

std::string SeccompPolicy::generate_snapshot_json() const {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"mode\": \"" << mode_name() << "\",\n";
    oss << "  \"allowed_syscall_count\": " << allowed_.size() << ",\n";
    oss << "  \"dangerous_syscalls\": [\n";
    for (size_t i = 0; i < dangerous_.size(); ++i) {
        const auto& ds = dangerous_[i];
        oss << "    {\"nr\": " << ds.nr
            << ", \"name\": \"" << ds.name << "\""
            << ", \"allowed\": " << (is_allowed(ds.nr) ? "true" : "false")
            << ", \"reason\": \"" << ds.reason << "\"}";
        if (i + 1 < dangerous_.size()) oss << ",";
        oss << "\n";
    }
    oss << "  ],\n";
    oss << "  \"param_filters\": [\n";
    for (size_t i = 0; i < param_filters_.size(); ++i) {
        const auto& pf = param_filters_[i];
        oss << "    {\"syscall_nr\": " << pf.syscall_nr
            << ", \"arg_index\": " << pf.arg_index
            << ", \"mask\": \"0x" << std::hex << pf.mask << "\""
            << ", \"value\": \"0x" << pf.value << std::dec << "\""
            << ", \"description\": \"" << pf.description << "\"}";
        if (i + 1 < param_filters_.size()) oss << ",";
        oss << "\n";
    }
    oss << "  ],\n";
    oss << "  \"default_action\": \"SECCOMP_RET_KILL_PROCESS\",\n";
    oss << "  \"hash\": \"" << compute_hash() << "\"\n";
    oss << "}\n";
    return oss.str();
}

std::string SeccompPolicy::compute_hash() const {
    std::ostringstream oss;
    oss << mode_name() << "|";
    for (int nr : allowed_) oss << nr << ",";
    oss << "|";
    for (const auto& pf : param_filters_) {
        oss << pf.syscall_nr << ":" << pf.arg_index << ":" << pf.mask << ":" << pf.value << ";";
    }
    std::string data = oss.str();

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), hash);

    std::ostringstream hex;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        hex << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return hex.str();
}

void SeccompPolicy::log_violation(const SeccompViolationEvent& event) {
    violation_count_++;
    // 实际实现中：写入审计日志文件 / 发送到审计 gRPC 流
    // 这里记录到 stderr（开发调试用），生产环境由 AuditLogger 接管
    fprintf(stderr,
        "[SECCOMP VIOLATION] ts=%lu pid=%d syscall=%d(%s) mode=%s killed=%d\n",
        event.timestamp_ns, event.pid, event.syscall_nr,
        event.syscall_name.c_str(), event.mode.c_str(), event.killed);
}

uint64_t SeccompPolicy::violation_count() {
    return violation_count_;
}

std::set<int> SeccompPolicy::parse_strace_syscalls(const std::string& strace_output) {
    std::set<int> result;
    // 解析 strace -c 输出或原始 strace 输出中的 syscall 名称
    // 简化实现：按行解析，提取常见模式
    std::istringstream iss(strace_output);
    std::string line;
    while (std::getline(iss, line)) {
        // strace 原始输出格式: syscall_name(args...) = result
        // strace -c 输出格式: % time seconds usecs/call calls errors syscall
        size_t paren = line.find('(');
        if (paren != std::string::npos && paren > 0 && paren < 64) {
            std::string name = line.substr(0, paren);
            // 去除前导空白
            size_t start = name.find_first_not_of(" \t");
            if (start != std::string::npos) {
                name = name.substr(start);
                // 简单的名称到号的映射（实际应使用 syscall 表）
                // 这里只做收集，返回空集合表示需要完整映射表
            }
        }
    }
    return result;
}

} // namespace sandbox
} // namespace photon_kernel
