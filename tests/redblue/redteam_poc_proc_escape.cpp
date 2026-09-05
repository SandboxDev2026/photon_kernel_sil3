/*
 * POC-009: /proc 接口突破限制
 *
 * 攻击技术：利用 /proc 文件系统接口突破沙盒限制
 * - /proc/self/mem: 直接读写进程内存（修改代码段）
 * - /proc/self/maps: 读取内存布局（寻找可写可执行区域）
 * - /proc/sysrq-trigger: 触发系统请求键（需要特权）
 * - /proc/sys/kernel/: 修改内核参数
 * - /proc/1/: 访问 init 进程信息
 * - /proc/self/fd/: 通过 fd 访问已打开的文件
 * - /proc/self/root: 访问根目录（chroot 绕过）
 * - /proc/self/cwd: 访问当前工作目录
 *
 * 预期行为：
 * - Landlock 限制 /proc 敏感路径访问
 * - seccomp 拦截 openat 对 /proc/sysrq-trigger 等路径
 * - /proc/self/mem 写入被阻止（PTRACE 模式要求）
 * - 进程被杀死或操作被拒绝
 *
 * 风险等级：High
 * 攻击面：LightPool /proc 文件系统隔离
 * 参考：CWE-22 (Path Traversal), CWE-73 (External Control of File Name or Path)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <signal.h>

#define TEST_COUNT 8

static int test_results[TEST_COUNT] = {0};

/* 测试 1: /proc/self/mem 写入（修改代码段） */
static void test_proc_self_mem(void) {
    printf("--- 测试 1: /proc/self/mem 写入 ---\n");
    int fd = open("/proc/self/mem", O_RDWR);
    if (fd >= 0) {
        printf("[!] /proc/self/mem 可写！(内存修改漏洞)\n");
        /* 尝试写入代码段 */
        unsigned char *code = (unsigned char *)test_proc_self_mem;
        lseek(fd, (off_t)code, SEEK_SET);
        unsigned char nop = 0x90;
        ssize_t n = write(fd, &nop, 1);
        if (n == 1) {
            printf("[!] 成功写入代码段！(任意代码执行)\n");
            test_results[0] = 1;
        } else {
            printf("[+] 写入被阻止: %s\n", strerror(errno));
        }
        close(fd);
    } else {
        printf("[+] /proc/self/mem 打开被拒绝: %s\n", strerror(errno));
    }
}

/* 测试 2: /proc/sysrq-trigger */
static void test_proc_sysrq(void) {
    printf("\n--- 测试 2: /proc/sysrq-trigger ---\n");
    int fd = open("/proc/sysrq-trigger", O_WRONLY);
    if (fd >= 0) {
        printf("[!] /proc/sysrq-trigger 可写！(系统请求键漏洞)\n");
        write(fd, "h", 1);  /* 显示帮助信息 */
        close(fd);
        test_results[1] = 1;
    } else {
        printf("[+] /proc/sysrq-trigger 打开被拒绝: %s\n", strerror(errno));
    }
}

/* 测试 3: /proc/sys/kernel/ 修改 */
static void test_proc_sys_kernel(void) {
    printf("\n--- 测试 3: /proc/sys/kernel/ 修改 ---\n");
    const char *paths[] = {
        "/proc/sys/kernel/hostname",
        "/proc/sys/kernel/domainname",
        "/proc/sys/kernel/pty/max",
        "/proc/sys/kernel/sched_child_runs_first",
    };
    for (int i = 0; i < 4; i++) {
        int fd = open(paths[i], O_WRONLY);
        if (fd >= 0) {
            printf("[!] %s 可写！(内核参数修改漏洞)\n", paths[i]);
            close(fd);
            test_results[2] = 1;
        }
    }
    if (!test_results[2]) {
        printf("[+] 所有 /proc/sys/kernel/ 路径均不可写\n");
    }
}

/* 测试 4: /proc/1/ 访问 */
static void test_proc_pid_1(void) {
    printf("\n--- 测试 4: /proc/1/ 访问 ---\n");
    const char *paths[] = {
        "/proc/1/mem",
        "/proc/1/maps",
        "/proc/1/environ",
        "/proc/1/root",
        "/proc/1/cwd",
    };
    for (int i = 0; i < 5; i++) {
        int fd = open(paths[i], O_RDONLY);
        if (fd >= 0) {
            printf("[!] %s 可读！(init 进程信息泄露)\n", paths[i]);
            close(fd);
            test_results[3] = 1;
        }
    }
    if (!test_results[3]) {
        printf("[+] /proc/1/ 所有路径均不可读\n");
    }
}

/* 测试 5: /proc/self/root 符号链接跟随 */
static void test_proc_self_root(void) {
    printf("\n--- 测试 5: /proc/self/root 符号链接 ---\n");
    char buf[256];
    ssize_t len = readlink("/proc/self/root", buf, sizeof(buf) - 1);
    if (len > 0) {
        buf[len] = '\0';
        printf("[*] /proc/self/root -> %s\n", buf);
        /* 尝试通过 /proc/self/root 访问宿主机文件 */
        int fd = open("/proc/self/root/etc/shadow", O_RDONLY);
        if (fd >= 0) {
            printf("[!] 通过 /proc/self/root 读取 /etc/shadow 成功！(chroot 绕过)\n");
            close(fd);
            test_results[4] = 1;
        } else {
            printf("[+] /proc/self/root/etc/shadow 访问被拒绝: %s\n", strerror(errno));
        }
    } else {
        printf("[+] readlink /proc/self/root 失败: %s\n", strerror(errno));
    }
}

/* 测试 6: /proc/self/fd/ 访问 */
static void test_proc_self_fd(void) {
    printf("\n--- 测试 6: /proc/self/fd/ 访问 ---\n");
    /* 打开一个文件，然后通过 /proc/self/fd/ 重新访问 */
    int fd = open("/tmp/test_fd_file.txt", O_CREAT | O_RDWR, 0644);
    if (fd < 0) {
        printf("[-] 无法创建测试文件: %s\n", strerror(errno));
        return;
    }
    write(fd, "secret data", 11);

    char fd_path[64];
    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);

    /* 通过 /proc/self/fd/ 重新打开 */
    int fd2 = open(fd_path, O_RDONLY);
    if (fd2 >= 0) {
        char buf[32];
        read(fd2, buf, sizeof(buf));
        printf("[*] 通过 /proc/self/fd/ 读取: %s\n", buf);
        /* 这在正常情况下是允许的（访问自己的 fd），但如果 fd 是继承的特权 fd 则危险 */
        close(fd2);
    }
    close(fd);
    unlink("/tmp/test_fd_file.txt");
    printf("[+] /proc/self/fd/ 访问正常（自己的 fd 可访问，继承 fd 需检查）\n");
}

/* 测试 7: /proc/kcore 访问 */
static void test_proc_kcore(void) {
    printf("\n--- 测试 7: /proc/kcore 访问 ---\n");
    int fd = open("/proc/kcore", O_RDONLY);
    if (fd >= 0) {
        printf("[!] /proc/kcore 可读！(内核内存转储漏洞)\n");
        close(fd);
        test_results[5] = 1;
    } else {
        printf("[+] /proc/kcore 访问被拒绝: %s\n", strerror(errno));
    }
}

/* 测试 8: /proc/modules 读取（内核模块信息） */
static void test_proc_modules(void) {
    printf("\n--- 测试 8: /proc/modules 读取 ---\n");
    int fd = open("/proc/modules", O_RDONLY);
    if (fd >= 0) {
        char buf[1024];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            printf("[*] /proc/modules 可读（内核模块信息泄露，用于内核漏洞利用）\n");
            printf("[*] 前 100 字符: %.100s\n", buf);
            /* 这通常是允许的，但在严格沙箱中应限制 */
        }
        close(fd);
    } else {
        printf("[+] /proc/modules 访问被拒绝: %s\n", strerror(errno));
    }
}

int main(void) {
    int bypass_found = 0;

    printf("[*] POC-009: /proc 接口突破限制测试\n");
    printf("[*] 目标：验证 /proc 文件系统敏感路径访问控制\n\n");

    test_proc_self_mem();
    test_proc_sysrq();
    test_proc_sys_kernel();
    test_proc_pid_1();
    test_proc_self_root();
    test_proc_self_fd();
    test_proc_kcore();
    test_proc_modules();

    for (int i = 0; i < TEST_COUNT; i++) {
        bypass_found |= test_results[i];
    }

    printf("\n");
    if (bypass_found) {
        printf("[!] 结果：发现 /proc 接口突破漏洞！\n");
        printf("[!] 修复建议：Landlock 限制 /proc 敏感路径，seccomp 参数过滤 openat\n");
        return 2;
    } else {
        printf("[+] 结果：所有 /proc 敏感路径访问均被阻止\n");
        return 0;
    }
}
