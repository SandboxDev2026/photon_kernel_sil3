/*
 * POC-014: 内核信息泄露与侦察
 *
 * 攻击技术：收集内核和系统信息，为后续逃逸做准备
 * - /proc/version 内核版本
 * - /proc/sys/kernel/ 内核参数
 * - dmesg / syslog 内核日志
 * - /proc/config.gz 内核配置
 * - /proc/kallsyms 内核符号
 * - /proc/modules 内核模块
 * - CPU 信息（/proc/cpuinfo）用于侧信道
 * - 内存布局（/proc/iomem, /proc/ioports）
 *
 * 预期行为：
 * - 敏感内核信息不可访问
 * - dmesg 需要特权
 * - /proc/kallsyms 地址被隐藏（kptr_restrict）
 * - 进程被杀死或信息被拒绝
 *
 * 风险等级：Medium（信息泄露为后续攻击铺路）
 * 攻击面：LightPool /proc 信息隔离
 * 参考：CWE-200 (Information Exposure)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>

static int sensitive_found = 0;

static void check_file(const char *path, const char *desc, int sensitive) {
    int fd = open(path, O_RDONLY);
    if (fd >= 0) {
        char buf[512];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            if (sensitive) {
                printf("[!] %s 可读（敏感信息泄露！）: %.100s\n", desc, buf);
                sensitive_found = 1;
            } else {
                printf("[*] %s 可读: %.80s\n", desc, buf);
            }
        }
        close(fd);
    } else {
        printf("[+] %s 访问被拒绝 (errno=%d)\n", desc, errno);
    }
}

int main(void) {
    printf("[*] POC-014: 内核信息泄露与侦察测试\n\n");

    printf("=== 敏感内核信息 ===\n");
    check_file("/proc/kallsyms", "内核符号表", 1);
    check_file("/proc/kmsg", "内核消息缓冲区", 1);
    check_file("/proc/config.gz", "内核配置", 1);
    check_file("/proc/sysrq-trigger", "系统请求键", 1);
    check_file("/proc/kcore", "内核内存转储", 1);

    printf("\n=== 内核参数 ===\n");
    check_file("/proc/sys/kernel/osrelease", "内核版本", 0);
    check_file("/proc/sys/kernel/hostname", "主机名", 0);
    check_file("/proc/sys/kernel/dmesg_restrict", "dmesg限制", 0);
    check_file("/proc/sys/kernel/kptr_restrict", "内核指针限制", 0);
    check_file("/proc/sys/kernel/unprivileged_userns_clone", "用户命名空间", 1);

    printf("\n=== 硬件信息（侧信道准备）===\n");
    check_file("/proc/cpuinfo", "CPU信息", 0);
    check_file("/proc/meminfo", "内存信息", 0);
    check_file("/proc/iomem", "物理内存映射", 1);
    check_file("/proc/ioports", "IO端口", 1);

    printf("\n=== 内核日志 ===\n");
    /* 尝试 dmesg */
    int pipefd[2];
    if (pipe(pipefd) == 0) {
        pid_t pid = fork();
        if (pid == 0) {
            close(pipefd[0]);
            dup2(pipefd[1], STDOUT_FILENO);
            execlp("dmesg", "dmesg", NULL);
            _exit(1);
        }
        close(pipefd[1]);
        char buf[512];
        ssize_t n = read(pipefd[0], buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            printf("[!] dmesg 可读（内核日志泄露！）: %.100s\n", buf);
            sensitive_found = 1;
        } else {
            printf("[+] dmesg 访问被拒绝\n");
        }
        close(pipefd[0]);
        int status;
        waitpid(pid, &status, 0);
    }

    printf("\n");
    if (sensitive_found) {
        printf("[!] 结果：发现敏感内核信息泄露！\n");
        printf("[!] 修复建议：限制 /proc/kallsyms、dmesg、/proc/kcore 等敏感路径\n");
        return 2;
    }
    printf("[+] 结果：所有敏感内核信息访问均被阻止\n");
    return 0;
}
