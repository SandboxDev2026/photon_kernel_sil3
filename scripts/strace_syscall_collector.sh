#!/bin/bash
# strace syscall 采集工具
#
# 用途：采集 LightPool 沙盒进程实际使用的系统调用，用于裁剪 seccomp 白名单。
# 原理：通过 strace 跟踪进程，统计所有出现的 syscall，生成白名单建议。
#
# 用法：
#   ./scripts/strace_syscall_collector.sh <command> [args...]
#   ./scripts/strace_syscall_collector.sh --pid <pid>
#   ./scripts/strace_syscall_collector.sh --file <strace_output_file>
#
# 输出：
#   - syscall 统计报告（按使用频率排序）
#   - seccomp 白名单建议（JSON 格式）
#   - 未在默认白名单中的 syscall 警告

set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

OUTPUT_DIR="/tmp/strace_collect_$$"
STRACE_OUTPUT="$OUTPUT_DIR/strace.log"
SUMMARY_OUTPUT="$OUTPUT_DIR/summary.txt"
WHITELIST_OUTPUT="$OUTPUT_DIR/seccomp_whitelist.json"

mkdir -p "$OUTPUT_DIR"

# 默认 seccomp 白名单中的常见 syscall（用于对比）
DEFAULT_WHITELIST=(
    read write readv writev pread64 pwrite64 openat close stat fstat lstat
    newfstatat lseek dup dup2 dup3 fcntl flock fsync fdatasync truncate
    ftruncate getdents64 access faccessat faccessat2 pipe pipe2 tee
    splice vmsplice clone clone3 fork vfork execve execveat exit
    exit_group wait4 waitid getpid getppid gettid sched_yield
    sched_getaffinity sched_setaffinity sched_getscheduler
    sched_setscheduler sched_getparam sched_setparam prctl arch_prctl
    mmap munmap mprotect brk mremap msync mlock munlock mlockall
    munlockall mincore madvise process_madvise sigaction sigprocmask
    sigreturn sigaltstack kill tkill tgkill signalfd signalfd4
    timer_create timer_settime timer_gettime timer_getoverrun
    timer_delete setitimer getitimer clock_gettime clock_settime
    clock_getres clock_nanosleep nanosleep gettimeofday settimeofday
    time socket connect accept accept4 sendto recvfrom sendmsg recvmsg
    shutdown bind listen getsockname getpeername setsockopt getsockopt
    socketpair uname sysinfo getrandom getuid geteuid getgid getegid
    getgroups setgroups getresuid setresuid getresgid setresgid
    capget capset preadv pwritev preadv2 pwritev2 ioctl fadvise64
    fallocate renameat renameat2 linkat unlinkat mkdirat symlinkat
    readlinkat fchmodat fchownat utimensat copy_file_range statx
    memfd_create userfaultfd rseq landlock_create_ruleset
    landlock_add_rule landlock_restrict_self seccomp getcpu
    epoll_create epoll_create1 epoll_ctl epoll_wait epoll_pwait
    epoll_pwait2 eventfd eventfd2 poll ppoll select pselect6
    inotify_init inotify_init1 inotify_add_watch inotify_rm_watch
    futex set_robust_list get_robust_list bpf perf_event_open
)

usage() {
    echo "用法: $0 <command> [args...]"
    echo "       $0 --pid <pid>"
    echo "       $0 --file <strace_output_file>"
    echo ""
    echo "输出目录: $OUTPUT_DIR"
    exit 1
}

collect_from_command() {
    echo -e "${GREEN}=== 通过 strace 跟踪命令: $* ===${NC}"
    strace -f -tt -T -o "$STRACE_OUTPUT" "$@" 2>/dev/null || true
    echo "strace 输出: $STRACE_OUTPUT"
}

collect_from_pid() {
    local pid=$1
    echo -e "${GREEN}=== 通过 strace 附加到 PID: $pid ===${NC}"
    strace -f -tt -T -p "$pid" -o "$STRACE_OUTPUT" 2>/dev/null || true
}

collect_from_file() {
    local file=$1
    echo -e "${GREEN}=== 从已有 strace 输出文件采集: $file ===${NC}"
    cp "$file" "$STRACE_OUTPUT"
}

analyze_syscalls() {
    echo ""
    echo -e "${GREEN}=== syscall 统计分析 ===${NC}"

    if [ ! -f "$STRACE_OUTPUT" ]; then
        echo -e "${RED}错误: strace 输出文件不存在${NC}"
        return 1
    fi

    # 提取所有 syscall 名称（strace 格式: syscall_name(args...) = result）
    # 处理多进程 strace 输出（每行可能有 pid 前缀）
    grep -oE '[a-z_]+\(' "$STRACE_OUTPUT" | sed 's/($//' | sort | uniq -c | sort -rn > "$SUMMARY_OUTPUT"

    TOTAL_SYSCALLS=$(wc -l < "$SUMMARY_OUTPUT")
    echo "发现 $TOTAL_SYSCALLS 种不同的 syscall"
    echo ""

    # 显示前 30 个最常用的 syscall
    echo "最常用的 30 个 syscall:"
    head -30 "$SUMMARY_OUTPUT" | while read count name; do
        printf "  %5d  %s\n" "$count" "$name"
    done

    # 生成白名单 JSON
    echo ""
    echo -e "${GREEN}=== 生成 seccomp 白名单建议 ===${NC}"

    # 提取所有 syscall 名称
    awk '{print $2}' "$SUMMARY_OUTPUT" > "$OUTPUT_DIR/all_syscalls.txt"

    # 检查哪些 syscall 不在默认白名单中
    echo ""
    echo -e "${YELLOW}=== 未在默认白名单中的 syscall（需要人工审核）===${NC}"
    UNKNOWN_COUNT=0
    while read syscall; do
        found=0
        for default in "${DEFAULT_WHITELIST[@]}"; do
            if [ "$syscall" = "$default" ]; then
                found=1
                break
            fi
        done
        if [ "$found" -eq 0 ]; then
            echo "  ⚠️  $syscall"
            UNKNOWN_COUNT=$((UNKNOWN_COUNT+1))
        fi
    done < "$OUTPUT_DIR/all_syscalls.txt"

    if [ "$UNKNOWN_COUNT" -eq 0 ]; then
        echo "  ✅ 所有 syscall 都在默认白名单中"
    else
        echo ""
        echo -e "${YELLOW}共 $UNKNOWN_COUNT 个 syscall 不在默认白名单中，请人工审核是否需要添加${NC}"
    fi

    # 生成 JSON 白名单
    python3 -c "
import json, os

syscalls = []
with open('$OUTPUT_DIR/all_syscalls.txt') as f:
    for line in f:
        name = line.strip()
        if name:
            syscalls.append(name)

default_whitelist = $(printf '"%s",' "${DEFAULT_WHITELIST[@]}")
default_whitelist = [x for x in default_whitelist if x]

unknown = [s for s in syscalls if s not in default_whitelist]

result = {
    'total_syscalls': len(syscalls),
    'in_default_whitelist': len(syscalls) - len(unknown),
    'unknown_syscalls': unknown,
    'recommended_whitelist': syscalls,
    'note': '建议将 unknown_syscalls 人工审核后添加到 seccomp 白名单，或确认它们是误报'
}

with open('$WHITELIST_OUTPUT', 'w') as f:
    json.dump(result, f, indent=2)

print(f'白名单建议已生成: $WHITELIST_OUTPUT')
print(f'  总 syscall 数: {len(syscalls)}')
print(f'  在默认白名单中: {len(syscalls) - len(unknown)}')
print(f'  未知 syscall: {len(unknown)}')
"
}

# 主逻辑
if [ $# -eq 0 ]; then
    usage
fi

case $1 in
    --pid)
        if [ -z "${2:-}" ]; then
            echo "错误: --pid 需要参数"
            usage
        fi
        collect_from_pid "$2"
        ;;
    --file)
        if [ -z "${2:-}" ]; then
            echo "错误: --file 需要参数"
            usage
        fi
        collect_from_file "$2"
        ;;
    --help|-h)
        usage
        ;;
    *)
        collect_from_command "$@"
        ;;
esac

analyze_syscalls

echo ""
echo -e "${GREEN}=== 采集完成 ===${NC}"
echo "输出目录: $OUTPUT_DIR"
echo "  - strace 原始输出: $STRACE_OUTPUT"
echo "  - syscall 统计: $SUMMARY_OUTPUT"
echo "  - seccomp 白名单建议: $WHITELIST_OUTPUT"
