/*
 * POC-008: 信号竞争条件逃逸
 *
 * 攻击技术：利用信号处理（SIGSTOP/SIGCONT/SIGKILL）的竞争条件，
 * 在 seccomp 检查点之间暂停进程，修改内存或文件状态后恢复执行。
 * 同时测试 SECCOMP_RET_TRAP 信号处理绕过（如果配置了 TRAP 而非 KILL）。
 *
 * 预期行为：
 * - seccomp 使用 SECCOMP_RET_KILL_PROCESS（不使用 TRAP）
 * - 信号处理不能绕过 seccomp 过滤
 * - SIGSTOP 不能暂停在 seccomp 检查点之间
 * - 进程被直接杀死，不进入信号处理流程
 *
 * 风险等级：High
 * 攻击面：LightPool seccomp + 信号处理
 * 参考：CWE-362 (Concurrent Execution using Shared Resource with Improper Synchronization)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <setjmp.h>

static volatile sig_atomic_t trap_received = 0;
static volatile sig_atomic_t trap_syscall = -1;
static sigjmp_buf jump_buffer;

/* SIGSYS 处理函数：如果 seccomp 使用 RET_TRAP，会进入这里 */
static void sigsys_handler(int signo, siginfo_t *info, void *context) {
    (void)signo;
    (void)context;
    trap_received = 1;
    if (info) {
        trap_syscall = info->si_syscall;
    }
    /* 尝试跳回，绕过被拦截的系统调用 */
    siglongjmp(jump_buffer, 1);
}

/* 测试 1：SIGSYS 信号处理绕过（如果 seccomp 用了 RET_TRAP） */
static int test_sigsys_bypass(void) {
    struct sigaction sa;
    int result = 0;

    printf("--- 测试 1: SIGSYS 信号处理绕过 ---\n");

    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigsys_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSYS, &sa, NULL);

    if (sigsetjmp(jump_buffer, 1) == 0) {
        /* 尝试调用被禁止的系统调用（ptrace） */
        printf("[*] 尝试调用 ptrace()...\n");
        syscall(SYS_ptrace, 0, 0, 0, 0);
        printf("[!] ptrace() 未被阻止！(seccomp 绕过！)\n");
        result = 1;
    } else {
        /* 从信号处理函数跳回 */
        if (trap_received) {
            printf("[!] SIGSYS 信号被捕获（seccomp 使用了 RET_TRAP，存在绕过风险）\n");
            printf("[!] 系统调用号: %d\n", trap_syscall);
            result = 1;
        }
    }

    /* 恢复默认处理 */
    signal(SIGSYS, SIG_DFL);
    trap_received = 0;

    if (!result) {
        printf("[+] 进程被直接杀死（使用了 RET_KILL_PROCESS，无信号处理机会）\n");
    }

    return result;
}

/* 测试 2：SIGSTOP 暂停在系统调用中间 */
static int test_sigstop_race(void) {
    pid_t child;
    int status;
    int result = 0;

    printf("\n--- 测试 2: SIGSTOP 暂停竞争 ---\n");

    child = fork();
    if (child == 0) {
        /* 子进程：不断调用 open()，尝试在中间被暂停 */
        for (int i = 0; i < 1000; i++) {
            int fd = open("/etc/shadow", O_RDONLY);
            if (fd >= 0) {
                printf("[!] 子进程成功打开 /etc/shadow！(暂停后状态被修改)\n");
                close(fd);
                _exit(2);
            }
            usleep(100);
        }
        _exit(0);
    }

    /* 父进程：不断发送 SIGSTOP/SIGCONT */
    for (int i = 0; i < 50; i++) {
        kill(child, SIGSTOP);
        usleep(1000);
        kill(child, SIGCONT);
        usleep(1000);

        /* 检查子进程状态 */
        pid_t ret = waitpid(child, &status, WNOHANG);
        if (ret == child) {
            if (WIFEXITED(status) && WEXITSTATUS(status) == 2) {
                result = 1;
            }
            break;
        }
    }

    /* 确保子进程结束 */
    kill(child, SIGKILL);
    waitpid(child, &status, 0);

    if (!result) {
        printf("[+] SIGSTOP/SIGCONT 竞争未导致逃逸\n");
    }

    return result;
}

/* 测试 3：信号掩码与 seccomp 的交互 */
static int test_signal_mask(void) {
    sigset_t mask;
    int result = 0;

    printf("\n--- 测试 3: 信号掩码绕过 ---\n");

    /* 阻塞所有信号（包括 SIGSYS/SIGKILL 不能被阻塞，但测试其他信号） */
    sigfillset(&mask);
    sigdelset(&mask, SIGKILL);
    sigdelset(&mask, SIGSTOP);
    sigprocmask(SIG_BLOCK, &mask, NULL);

    /* 尝试调用被禁止的系统调用 */
    printf("[*] 阻塞信号后尝试调用 ptrace()...\n");
    pid_t child = fork();
    if (child == 0) {
        syscall(SYS_ptrace, 0, 0, 0, 0);
        /* 如果到达这里，说明没有被杀死 */
        _exit(2);
    }

    int status;
    waitpid(child, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 2) {
        printf("[!] 信号阻塞后 ptrace() 未被阻止！\n");
        result = 1;
    } else {
        printf("[+] 信号阻塞不能绕过 seccomp（进程被杀死）\n");
    }

    return result;
}

int main(void) {
    int bypass_found = 0;

    printf("[*] POC-008: 信号竞争条件逃逸测试\n");
    printf("[*] 目标：验证信号处理不能绕过 seccomp 过滤\n\n");

    /* 注意：测试 1 如果 seccomp 用了 KILL，子进程会被杀死
       所以在子进程中运行测试 1 */
    pid_t child = fork();
    if (child == 0) {
        int r = test_sigsys_bypass();
        _exit(r ? 2 : 0);
    }
    int status;
    waitpid(child, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 2) {
        bypass_found = 1;
    }

    bypass_found |= test_sigstop_race();
    bypass_found |= test_signal_mask();

    printf("\n");
    if (bypass_found) {
        printf("[!] 结果：发现信号相关逃逸漏洞！\n");
        printf("[!] 修复建议：使用 SECCOMP_RET_KILL_PROCESS，不要用 RET_TRAP\n");
        return 2;
    } else {
        printf("[+] 结果：所有信号竞争测试均被阻止\n");
        return 0;
    }
}
