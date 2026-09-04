// POC-004: seccomp 绕过尝试（红队对抗用例）
//
// 攻击技术：尝试多种 seccomp 绕过技巧
//   1. 32 位兼容模式 syscall（int 0x80）
//   2. syscall 号混淆（使用非标准号）
//   3. 间接 syscall（通过 vDSO/vsyscall）
//   4. 参数注入（openat 传入恶意 flag）
// 预期行为：全部被 seccomp BPF 拦截，进程被 KILL
// 风险等级：Critical
//
// 编译：g++ -o redteam_poc_seccomp_bypass redteam_poc_seccomp_bypass.cpp
// 在沙盒内运行：./redteam_poc_seccomp_bypass
// 预期：所有绕过尝试失败，无 syscall 成功执行

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sched.h>
#include <errno.h>
#include <errno.h>

// 内联汇编执行 32 位兼容模式 syscall（int 0x80）
// 在 x86_64 上，int 0x80 使用 32 位 syscall 号表
static inline long int80_syscall(long nr, long arg1, long arg2, long arg3) {
    long ret;
    __asm__ volatile(
        "int $0x80"
        : "=a"(ret)
        : "a"(nr), "b"(arg1), "c"(arg2), "d"(arg3)
        : "memory"
    );
    return ret;
}

// 直接 syscall 指令（x86_64）
static inline long direct_syscall(long nr, long arg1, long arg2, long arg3,
                                   long arg4, long arg5, long arg6) {
    long ret;
    register long r10 __asm__("r10") = arg4;
    register long r8 __asm__("r8") = arg5;
    register long r9 __asm__("r9") = arg6;
    __asm__ volatile(
        "syscall"
        : "=a"(ret)
        : "a"(nr), "D"(arg1), "S"(arg2), "d"(arg3), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory"
    );
    return ret;
}

int main() {
    printf("[POC-004] seccomp 绕过测试\n");
    printf("[POC-004] 尝试多种绕过技巧，预期全部被拦截\n\n");

    int bypass_success = 0;

    // === 技巧1: 32 位兼容模式 int 0x80 执行 ptrace ===
    // 32 位 ptrace 的 syscall 号是 26
    printf("[POC-004] 技巧1: int 0x80 执行 32 位 ptrace (nr=26)...\n");
    long ret1 = int80_syscall(26, 0, 0, 0); // PTRACE_TRACEME
    if (ret1 == 0) {
        printf("[POC-004] ❌ 32位 ptrace 成功！seccomp 未拦截 int 0x80\n");
        bypass_success++;
    } else {
        printf("[POC-004] ✅ 32位 ptrace 被拦截: errno=%d (%s)\n", errno, strerror(errno));
    }

    // === 技巧2: 使用非标准 syscall 号（保留号/未定义号）===
    printf("[POC-004] 技巧2: 执行未定义 syscall (nr=999)...\n");
    long ret2 = direct_syscall(999, 0, 0, 0, 0, 0, 0);
    if (ret2 != -ENOSYS) {
        printf("[POC-004] ⚠️  未定义 syscall 返回非 ENOSYS: %ld\n", ret2);
    } else {
        printf("[POC-004] ✅ 未定义 syscall 返回 ENOSYS（正常）\n");
    }

    // === 技巧3: openat 参数注入（O_WRONLY 访问 /proc/kcore）===
    printf("[POC-004] 技巧3: openat 尝试 O_WRONLY 访问 /proc/kcore...\n");
    int fd = openat(AT_FDCWD, "/proc/kcore", O_WRONLY);
    if (fd >= 0) {
        printf("[POC-004] ❌ /proc/kcore 可写打开！fd=%d\n", fd);
        close(fd);
        bypass_success++;
    } else {
        printf("[POC-004] ✅ /proc/kcore 打开被拒绝: errno=%d (%s)\n", errno, strerror(errno));
    }

    // === 技巧4: clone 传入 CLONE_NEWUSER（尝试新建 user namespace）===
    printf("[POC-004] 技巧4: clone(CLONE_NEWUSER) 尝试新建命名空间...\n");
    // 注意：实际 clone 需要栈，这里用 syscall 直接调用
    long ret4 = direct_syscall(SYS_clone, CLONE_NEWUSER | SIGCHLD, 0, 0, 0, 0, 0);
    if (ret4 == 0) {
        printf("[POC-004] ❌ CLONE_NEWUSER 成功！可以新建命名空间逃逸\n");
        _exit(0); // 子进程退出
    } else if (ret4 > 0) {
        printf("[POC-004] ❌ CLONE_NEWUSER 成功！父进程 pid=%ld\n", ret4);
        bypass_success++;
    } else {
        printf("[POC-004] ✅ CLONE_NEWUSER 被拒绝: errno=%d (%s)\n", errno, strerror(errno));
    }

    // === 技巧5: personality 设置为 32 位（尝试切换到 32 位模式绕过）===
    printf("[POC-004] 技巧5: personality(PER_LINUX32) 切换 32 位...\n");
    long ret5 = direct_syscall(SYS_personality, 0x0008, 0, 0, 0, 0, 0); // PER_LINUX32 = 0x0008
    if (ret5 >= 0) {
        printf("[POC-004] ⚠️  personality 切换成功（可能允许 32 位 syscall 绕过）\n");
        // 切换后再次尝试 int 0x80 ptrace
        long ret5b = int80_syscall(26, 0, 0, 0);
        if (ret5b == 0) {
            printf("[POC-004] ❌ personality 切换后 32 位 ptrace 成功！\n");
            bypass_success++;
        } else {
            printf("[POC-004] ✅ personality 切换后 32 位 ptrace 仍被拦截\n");
        }
    } else {
        printf("[POC-004] ✅ personality 被拒绝: errno=%d (%s)\n", errno, strerror(errno));
    }

    printf("\n[POC-004] 统计: 成功绕过 %d 次\n", bypass_success);

    if (bypass_success > 0) {
        printf("[POC-004] ❌ 发现 %d 个 seccomp 绕过漏洞！\n", bypass_success);
        return 1;
    } else {
        printf("[POC-004] ✅ 所有 seccomp 绕过尝试均被拦截\n");
        return 0;
    }
}
