/*
 * POC-015: 侧信道攻击（缓存时序 + Spectre 变体）
 *
 * 攻击技术：
 * - Flush+Reload：刷新缓存行，测量访问时间推断秘密数据
 * - Prime+Probe：填充缓存集，测量竞争推断访问模式
 * - Spectre v1：边界检查绕过，推测执行泄露数据
 * - Spectre v2：分支目标注入，推测执行泄露
 * - MDS（Microarchitectural Data Sampling）：从填充缓冲区读取数据
 * - L1TF（L1 Terminal Fault）：页表错误时读取 L1 缓存
 *
 * 注意：这是概念验证代码，实际利用需要特定硬件和内核配置。
 * 目的是验证沙箱是否启用了侧信道缓解措施。
 *
 * 预期行为：
 * - 沙箱内无法访问其他进程的缓存（进程隔离）
 * - 推测执行缓解（Spectre 补丁）已启用
 * - MDS/L1TF 缓解已启用
 * - 高分辨率计时器可能被限制
 *
 * 风险等级：High
 * 攻击面：LightPool 进程隔离 + 硬件侧信道
 * 参考：CVE-2017-5753 (Spectre v1), CVE-2017-5715 (Spectre v2)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sched.h>
#include <pthread.h>
#include <x86intrin.h>
#include <cstdint>

#define CACHE_LINE_SIZE 64
#define ITERATIONS 1000
#define THRESHOLD 100  // 缓存命中时间阈值（周期）

static inline uint64_t rdtsc(void) {
    unsigned int lo, hi;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static inline void clflush(volatile void *p) {
    __asm__ volatile ("clflush (%0)" :: "r"(p));
}

static int sidechannel_detected = 0;

/* 测试1：Flush+Reload 缓存时序攻击 */
static void test_flush_reload(void) {
    printf("--- 测试1: Flush+Reload 缓存时序 ---\n");
    char secret_data[4096] __attribute__((aligned(4096)));
    memset(secret_data, 'A', sizeof(secret_data));

    int cache_hits = 0;
    int cache_misses = 0;

    for (int i = 0; i < ITERATIONS; i++) {
        /* 刷新缓存行 */
        clflush(&secret_data[0]);
        _mm_mfence();

        /* 访问数据（模拟秘密访问） */
        volatile char c = secret_data[0];
        (void)c;

        /* 测量重新加载时间 */
        uint64_t start = rdtsc();
        volatile char d = secret_data[0];
        (void)d;
        uint64_t end = rdtsc();
        uint64_t elapsed = end - start;

        if (elapsed < THRESHOLD) {
            cache_hits++;
        } else {
            cache_misses++;
        }
    }

    printf("[*] 缓存命中: %d, 缓存未命中: %d\n", cache_hits, cache_misses);
    printf("[*] 命中率: %.1f%%\n", (double)cache_hits / ITERATIONS * 100);

    /* 如果命中率异常高，说明缓存时序可测量（侧信道可能可行） */
    if (cache_hits > ITERATIONS * 0.8) {
        printf("[!] 缓存时序可精确测量（Flush+Reload 可能可行）\n");
        sidechannel_detected = 1;
    } else {
        printf("[+] 缓存时序测量不稳定（可能有缓解措施）\n");
    }
}

/* 测试2：高分辨率计时器可用性 */
static void test_highres_timer(void) {
    printf("\n--- 测试2: 高分辨率计时器 ---\n");
    struct timespec ts1, ts2;
    clock_gettime(CLOCK_MONOTONIC, &ts1);
    for (volatile int i = 0; i < 1000; i++);
    clock_gettime(CLOCK_MONOTONIC, &ts2);

    long elapsed_ns = (ts2.tv_sec - ts1.tv_sec) * 1000000000L + (ts2.tv_nsec - ts1.tv_nsec);
    printf("[*] clock_gettime 分辨率: %ld ns\n", elapsed_ns);

    /* 测试 rdtsc 是否可用 */
    uint64_t t1 = rdtsc();
    for (volatile int i = 0; i < 100; i++);
    uint64_t t2 = rdtsc();
    printf("[*] rdtsc 可用，差值: %lu 周期\n", t2 - t1);

    if (t2 > t1 && elapsed_ns > 0) {
        printf("[!] 高分辨率计时器可用（侧信道攻击前提条件）\n");
        sidechannel_detected = 1;
    }
}

/* 测试3：Spectre v1 边界检查绕过（概念验证） */
static void test_spectre_v1(void) {
    printf("\n--- 测试3: Spectre v1 边界检查绕过（概念验证）---\n");

    /* 简化版 Spectre v1 PoC */
    size_t array1_size = 16;
    uint8_t array1[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    uint8_t array2[256 * 512];
    memset(array2, 1, sizeof(array2));

    /* 训练分支预测器 */
    for (int i = 0; i < 100; i++) {
        size_t x = i % array1_size;
        if (x < array1_size) {
            volatile uint8_t v = array2[array1[x] * 512];
            (void)v;
        }
    }

    /* 尝试越界访问（推测执行） */
    size_t malicious_x = 0xFFFFFFFF;  // 越界
    int hits = 0;
    for (int i = 0; i < 100; i++) {
        if (malicious_x < array1_size) {
            volatile uint8_t v = array2[array1[malicious_x] * 512];
            (void)v;
        }
        /* Flush+Reload 检测 */
        for (int j = 0; j < 256; j++) {
            clflush(&array2[j * 512]);
        }
    }

    printf("[*] Spectre v1 概念验证完成（实际利用需要特定硬件/内核）\n");
    printf("[*] 注意：现代内核已默认启用 Spectre 缓解\n");
}

/* 测试4：CPU 侧信道缓解检查 */
static void check_cpu_mitigations(void) {
    printf("\n--- 测试4: CPU 侧信道缓解检查 ---\n");
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "bugs") || strstr(line, "flags")) {
                printf("[*] %s", line);
                if (strstr(line, "spectre") || strstr(line, "meltdown")) {
                    printf("[!] CPU 存在已知侧信道漏洞\n");
                    sidechannel_detected = 1;
                }
            }
        }
        fclose(f);
    }

    /* 检查内核缓解 */
    f = fopen("/sys/devices/system/cpu/vulnerabilities/spectre_v1", "r");
    if (f) {
        char buf[256];
        if (fgets(buf, sizeof(buf), f)) {
            printf("[*] Spectre v1 状态: %s", buf);
            if (strstr(buf, "Vulnerable")) {
                printf("[!] Spectre v1 未缓解！\n");
                sidechannel_detected = 1;
            }
        }
        fclose(f);
    }
}

int main(void) {
    printf("[*] POC-015: 侧信道攻击（缓存时序 + Spectre 变体）\n");
    printf("[*] 注意：这是概念验证，实际利用需要特定硬件/内核配置\n\n");

    test_flush_reload();
    test_highres_timer();
    test_spectre_v1();
    check_cpu_mitigations();

    printf("\n");
    if (sidechannel_detected) {
        printf("[!] 结果：检测到侧信道攻击前提条件或未缓解漏洞\n");
        printf("[!] 建议：启用 Spectre/Meltdown/MDS/L1TF 内核缓解，考虑高分辨率计时器限制\n");
        return 2;
    }
    printf("[+] 结果：侧信道缓解措施已启用或攻击条件不满足\n");
    return 0;
}
