#include <gtest/gtest.h>

#include <sys/syscall.h>
#include <thread>
#include <atomic>
#include <vector>

#include "photon_kernel/sandbox/sandboxed_executor.hpp"

using namespace photon_kernel::sandbox;

// 测试1：正常任务（参考 JudgeServer 基础测试）
TEST(SandboxTest, NormalTask) {
    SandboxConfig cfg = SandboxConfig::for_risk_level(RiskLevel::LOW);
    SandboxedExecutor exec(cfg);
    SandboxedTask task;
    task.name = "Normal";
    task.func = []() { volatile int x = 0; for (int i = 0; i < 10000; ++i) x += i; };
    auto result = exec.execute_sync(task);
    EXPECT_TRUE(result.success);
}

// 测试2：内存炸弹（参考 JudgeServer MLE 测试）
TEST(SandboxTest, MemoryBomb) {
    SandboxConfig cfg = SandboxConfig::for_risk_level(RiskLevel::HIGH);
    cfg.memory_limit_bytes = 5 * 1024 * 1024;
    SandboxedExecutor exec(cfg);
    SandboxedTask task;
    task.name = "MemoryBomb";
    task.func = []() {
        volatile char* p = new char[10 * 1024 * 1024];
        for (size_t i = 0; i < 10 * 1024 * 1024; ++i) p[i] = 0;
        delete[] p;
    };
    auto result = exec.execute_sync(task);
    EXPECT_FALSE(result.success);
}

// 测试3：死循环（参考 JudgeServer TLE 测试）
TEST(SandboxTest, InfiniteLoop) {
    SandboxConfig cfg = SandboxConfig::for_risk_level(RiskLevel::MEDIUM);
    cfg.cpu_time_limit = std::chrono::seconds(1);
    SandboxedExecutor exec(cfg);
    SandboxedTask task;
    task.name = "InfiniteLoop";
    task.timeout = std::chrono::milliseconds(500);
    task.func = []() { while (true) {}; };
    auto result = exec.execute_sync(task);
    EXPECT_FALSE(result.success);
    EXPECT_EQ(result.error_code, SandboxErrorCode::TIMEOUT_EXPIRED);
}

// 测试4：fork炸弹（参考 JudgeServer 进程限制测试）
TEST(SandboxTest, ForkBomb) {
    SandboxConfig cfg = SandboxConfig::for_risk_level(RiskLevel::MEDIUM);
    SandboxedExecutor exec(cfg);
    SandboxedTask task;
    task.name = "ForkBomb";
    task.timeout = std::chrono::milliseconds(2000);
    task.func = []() { while (true) fork(); };
    auto result = exec.execute_sync(task);
    EXPECT_FALSE(result.success);
}

// 测试5：非法syscall（seccomp 拦截 → KILL_PROCESS → SIGSYS）
TEST(SandboxTest, IllegalSyscall) {
    SandboxConfig cfg = SandboxConfig::for_risk_level(RiskLevel::HIGH);
    SandboxedExecutor exec(cfg);
    SandboxedTask task;
    task.name = "Illegal";
    task.func = []() { syscall(SYS_socket, 1, 1, 0); };
    auto result = exec.execute_sync(task);
    EXPECT_FALSE(result.success);
}

// 测试6：批量执行隔离（参考 JudgeServer 批量测试）
TEST(SandboxTest, BatchIsolation) {
    SandboxConfig cfg = SandboxConfig::for_risk_level(RiskLevel::LOW);
    SandboxedExecutor exec(cfg);

    SandboxedTask good1;
    good1.name = "Good1";
    good1.func = []() { volatile int x = 0; (void)x; };
    SandboxedTask bad;
    bad.name = "Bad";
    bad.func = []() { while (true) {}; };
    SandboxedTask good2;
    good2.name = "Good2";
    good2.func = []() { volatile int y = 1; (void)y; };

    std::vector<SandboxedTask> tasks{good1, bad, good2};
    auto results = exec.execute_batch(tasks);
    EXPECT_TRUE(results[0].success);
    EXPECT_FALSE(results[1].success);
    EXPECT_TRUE(results[2].success);
}

// 测试7：并发压力（50个并发任务）
TEST(SandboxTest, Concurrency) {
    SandboxConfig cfg = SandboxConfig::for_risk_level(RiskLevel::MEDIUM);
    SandboxedExecutor exec(cfg);
    const int N = 50;
    std::vector<std::future<SandboxResult>> futures;
    for (int i = 0; i < N; ++i) {
        SandboxedTask task;
        task.name = "Concurrent_" + std::to_string(i);
        task.func = []() { volatile int x = 0; for (int j = 0; j < 5000; ++j) x += j; };
        futures.push_back(exec.execute_async(task));
    }
    int success = 0;
    for (auto& f : futures) if (f.get().success) success++;
    EXPECT_GT(success, N * 0.8);
    EXPECT_EQ(exec.get_total_tasks_executed(), N);
}

// 测试8：统计信息
TEST(SandboxTest, Statistics) {
    SandboxConfig cfg = SandboxConfig::for_risk_level(RiskLevel::MEDIUM);
    SandboxedExecutor exec(cfg);

    SandboxedTask good1;
    good1.name = "Good";
    good1.func = []() { volatile int x = 0; (void)x; };
    exec.execute_sync(good1);

    SandboxedTask bad;
    bad.name = "Bad";
    bad.timeout = std::chrono::milliseconds(100);
    bad.func = []() { while (true) {}; };
    exec.execute_sync(bad);

    SandboxedTask good2;
    good2.name = "Good2";
    good2.func = []() { volatile int y = 1; (void)y; };
    exec.execute_sync(good2);

    EXPECT_EQ(exec.get_total_tasks_executed(), 3);
    EXPECT_GT(exec.get_total_failures(), 0);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
