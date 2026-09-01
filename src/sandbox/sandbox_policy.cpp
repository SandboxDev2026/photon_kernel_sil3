#include "photon_kernel/sandbox/sandbox_policy.hpp"
#include "photon_kernel/sandbox/sandbox_exception.hpp"

#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstring>
#include <algorithm>
#include <fstream>
#include <iostream>

#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif

namespace photon_kernel {
namespace sandbox {

// ---- 基础白名单（参考 NsJail seccomp_policy.cpp 的默认允许列表） ----
// 注意：基础白名单包含只读文件访问（openat/readlinkat/getdents64 等），
// 供 MEDIUM（只读文件、无网络）等级使用；HIGH 等级会在下方显式移除这些调用。
static std::vector<int> get_base_whitelist() {
    std::vector<int> w = {
        // 基础 I/O
        __NR_read, __NR_write, __NR_close,
        __NR_lseek, __NR_fstat, __NR_newfstatat,
        __NR_openat, __NR_readlinkat, __NR_readlink,
        __NR_getdents64, __NR_faccessat,
        // 内存管理
        __NR_mmap, __NR_munmap, __NR_mprotect, __NR_brk,
        __NR_madvise, __NR_mlock, __NR_munlock, __NR_mremap,
#ifdef __NR_membarrier
        __NR_membarrier,
#endif
#ifdef __NR_arch_prctl
        __NR_arch_prctl,
#endif
        // 进程/线程
        __NR_exit, __NR_exit_group, __NR_getpid, __NR_gettid,
        __NR_getuid, __NR_geteuid, __NR_getgid, __NR_getegid,
        __NR_futex, __NR_set_tid_address, __NR_set_robust_list,
        __NR_get_robust_list, __NR_sched_yield, __NR_getcpu,
#ifdef __NR_clone
        __NR_clone,
#endif
#ifdef __NR_clone3
        __NR_clone3,
#endif
#ifdef __NR_fork
        __NR_fork,
#endif
#ifdef __NR_vfork
        __NR_vfork,
#endif
        // 时间
        __NR_clock_gettime, __NR_clock_getres, __NR_gettimeofday,
        __NR_nanosleep, __NR_clock_nanosleep, __NR_time,
        // 信号
        __NR_rt_sigprocmask, __NR_rt_sigaction, __NR_rt_sigreturn,
        __NR_rt_sigpending, __NR_rt_sigtimedwait,
        // 系统信息
        __NR_uname, __NR_sysinfo, __NR_getrandom,
        // 沙盒自省
        __NR_prctl,
        // 其他常用
        __NR_munlockall, __NR_getrusage, __NR_times,
        __NR_getrlimit, __NR_prlimit64, __NR_rseq,
        // fd 操作
        __NR_dup, __NR_dup2, __NR_dup3, __NR_fcntl,
        __NR_pipe, __NR_pipe2, __NR_socketpair,
        __NR_poll, __NR_ppoll, __NR_epoll_create1,
        __NR_epoll_ctl, __NR_epoll_wait, __NR_eventfd2,
        // 等待子进程
        __NR_wait4, __NR_waitid
    };

    // 去重
    std::sort(w.begin(), w.end());
    w.erase(std::unique(w.begin(), w.end()), w.end());
    return w;
}

// ---- 根据风险等级构造白名单（参考 NsJail 多策略） ----
std::vector<int> SandboxPolicy::get_whitelist_for_risk(RiskLevel level) {
    auto whitelist = get_base_whitelist();

    if (level == RiskLevel::LOW) {
        // 低风险：允许网络、socket、文件写入
        whitelist.insert(whitelist.end(), {
            __NR_socket, __NR_connect, __NR_accept, __NR_accept4,
            __NR_bind, __NR_listen, __NR_sendto, __NR_recvfrom,
            __NR_getsockname, __NR_getpeername,
            __NR_setsockopt, __NR_getsockopt, __NR_shutdown,
            __NR_open, __NR_creat, __NR_unlink, __NR_rename,
            __NR_writev, __NR_readv, __NR_pwrite64, __NR_pread64
        });
    } else if (level == RiskLevel::MEDIUM) {
        // 中风险：只读文件、无网络。基础白名单已包含 openat/readlinkat/getdents64 等只读能力，
        // 同时未加入 socket/网络调用，天然禁止网络。
    } else { // HIGH
        // 高风险：移除所有文件操作，仅保留最低限度的系统调用
        std::vector<int> remove_list = {
            __NR_openat, __NR_open, __NR_readlinkat, __NR_readlink,
            __NR_getdents64, __NR_faccessat,
            __NR_lseek, __NR_fstat, __NR_newfstatat,
            __NR_creat, __NR_unlink, __NR_rename
        };
        for (int sc : remove_list) {
            whitelist.erase(std::remove(whitelist.begin(), whitelist.end(), sc),
                            whitelist.end());
        }
    }

    return whitelist;
}

// ---- 代码执行白名单：在 LOW 基础上追加 execve / 进程管理 / 临时文件等 ----
// 注意：seccomp 无法按“路径”过滤（无法解引用用户指针），解释器路径白名单
// 由调用方硬编码（CodeRunner 只允许 /usr/bin/python3、/usr/bin/node、/bin/sh）。
std::vector<int> SandboxPolicy::get_whitelist_for_code_runner() {
    auto w = get_whitelist_for_risk(RiskLevel::LOW);

    std::vector<int> extra = {
        // 进程创建与解释器执行
        __NR_execve,
#ifdef __NR_execveat
        __NR_execveat,
#endif
        // 进程信号（看门狗超时 kill 任务进程）
        __NR_kill, __NR_tkill, __NR_tgkill,
        // 临时输出文件
        __NR_unlink, __NR_unlinkat,
        __NR_fsync, __NR_fdatasync,
        // 解释器运行所需
        __NR_ioctl,
        __NR_select,
#ifdef __NR_pselect6
        __NR_pselect6,
#endif
        __NR_getdents,
        __NR_getcwd, __NR_chdir, __NR_fchdir,
        __NR_mkdir, __NR_mkdirat,
        // shell(POSIX sh/dash) 运行时所需
        __NR_sigaltstack, __NR_umask,
        __NR_statfs, __NR_fstatfs,
        __NR_getppid, __NR_setsid, __NR_getsid,
        __NR_setpgid, __NR_getpgid,
        __NR_dup3,
#ifdef __NR_stat
        __NR_stat,
#endif
#ifdef __NR_access
        __NR_access,
#endif
#ifdef __NR_readlink
        __NR_readlink,
#endif
    };

    return merge_with_extra(w, extra);
}

// 参考：NsJail 合并额外系统调用
std::vector<int> SandboxPolicy::merge_with_extra(
    const std::vector<int>& base,
    const std::vector<int>& extra) {
    std::vector<int> result = base;
    for (int syscall_num : extra) {
        if (std::find(result.begin(), result.end(), syscall_num) == result.end()) {
            result.push_back(syscall_num);
        }
    }
    return result;
}

// ---- 安装 seccomp 过滤器（参考 libseccomp 官方示例 + NsJail） ----
void SandboxPolicy::install_seccomp_filter(const std::vector<int>& allowed_syscalls) {
#if defined(__linux__) && defined(__x86_64__)
    // PR_SET_NO_NEW_PRIVS: 参考 bubblewrap 标准写法
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        throw SandboxException(SandboxErrorCode::SECCOMP_INSTALL_FAILED,
            "prctl(PR_SET_NO_NEW_PRIVS) failed");
    }

    // 构造 BPF 过滤器：参考 NsJail 的 seccomp-bpf 实现
    std::vector<struct sock_filter> filter;
    filter.push_back(BPF_STMT(BPF_LD + BPF_W + BPF_ABS,
                              offsetof(struct seccomp_data, nr)));

    for (int syscall_num : allowed_syscalls) {
        filter.push_back(BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,
                                  static_cast<uint32_t>(syscall_num), 0, 1));
        filter.push_back(BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW));
    }

    // 默认拒绝：直接杀死进程（KILL_PROCESS），保证非法系统调用被彻底拦截
#ifdef SECCOMP_RET_KILL_PROCESS
    filter.push_back(BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL_PROCESS));
#else
    filter.push_back(BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL));
#endif

    struct sock_fprog prog;
    prog.len = static_cast<unsigned short>(filter.size());
    prog.filter = filter.data();

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) != 0) {
        throw SandboxException(SandboxErrorCode::SECCOMP_INSTALL_FAILED,
            "prctl(PR_SET_SECCOMP) failed: " + std::string(strerror(errno)));
    }

    std::cerr << "[Sandbox] seccomp-bpf installed (" << allowed_syscalls.size()
              << " syscalls allowed)\n";
#else
    std::cerr << "[Sandbox] WARNING: seccomp not supported on this platform.\n";
#endif
}

// ---- 设置 rlimit（参考 NsJail + JudgeServer） ----
void SandboxPolicy::apply_rlimits(const SandboxConfig& config, bool apply_nproc) {
    struct rlimit rlim;

    // 内存（RLIMIT_AS）
    rlim.rlim_cur = config.memory_limit_bytes;
    rlim.rlim_max = config.memory_limit_bytes;
    if (setrlimit(RLIMIT_AS, &rlim) != 0) {
        throw SandboxException(SandboxErrorCode::RESOURCE_LIMIT_EXCEEDED,
            "setrlimit(RLIMIT_AS) failed");
    }

    // CPU 时间（RLIMIT_CPU）
    rlim.rlim_cur = static_cast<rlim_t>(config.cpu_time_limit.count());
    rlim.rlim_max = static_cast<rlim_t>(config.cpu_time_limit.count()) + 1;
    if (setrlimit(RLIMIT_CPU, &rlim) != 0) {
        throw SandboxException(SandboxErrorCode::RESOURCE_LIMIT_EXCEEDED,
            "setrlimit(RLIMIT_CPU) failed");
    }

    // 进程数（防 fork 炸弹）：预 fork worker 场景由任务进程内部单独设置，
    // 避免 worker 因 NPROC 收紧而无法继续 fork 任务进程
    if (apply_nproc) {
        rlim.rlim_cur = config.process_limit;
        rlim.rlim_max = config.process_limit;
        if (setrlimit(RLIMIT_NPROC, &rlim) != 0) {
            // 非致命，某些系统可能不允许（例如非 root 提高 RLIMIT_NPROC），忽略
        }
    }

    // 文件大小
    rlim.rlim_cur = config.file_size_limit;
    rlim.rlim_max = config.file_size_limit;
    setrlimit(RLIMIT_FSIZE, &rlim);

    // ---- DoS 防护增强：补齐剩余 rlimit ----
    // 核心转储：禁用（防止恶意代码生成大 core 文件耗尽磁盘）
    rlim.rlim_cur = 0;
    rlim.rlim_max = 0;
    setrlimit(RLIMIT_CORE, &rlim);

    // 文件描述符数：防止 fd 耗尽攻击（每个连接/文件占一个 fd）
    rlim.rlim_cur = static_cast<rlim_t>(config.nofile_limit);
    rlim.rlim_max = static_cast<rlim_t>(config.nofile_limit);
    setrlimit(RLIMIT_NOFILE, &rlim);

    // 挂起信号数：防止信号队列耗尽
    rlim.rlim_cur = static_cast<rlim_t>(config.sigpending_limit);
    rlim.rlim_max = static_cast<rlim_t>(config.sigpending_limit);
    setrlimit(RLIMIT_SIGPENDING, &rlim);

    // 消息队列字节数：防止 POSIX 消息队列耗尽内核内存
    rlim.rlim_cur = static_cast<rlim_t>(config.msgqueue_limit);
    rlim.rlim_max = static_cast<rlim_t>(config.msgqueue_limit);
    setrlimit(RLIMIT_MSGQUEUE, &rlim);

    // OOM 分数调整：沙盒子进程优先被 OOM killer 选中（保护宿主）
    // oom_score_adj 范围 -1000~1000，1000 表示最优先被杀
    {
        std::ofstream oom("/proc/self/oom_score_adj");
        if (oom.good()) oom << "1000";
    }
}

} // namespace sandbox
} // namespace photon_kernel
