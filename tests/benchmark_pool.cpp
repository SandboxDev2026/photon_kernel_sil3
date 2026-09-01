// 预热池 vs 直接 fork 的基准测试（需安装 google/benchmark）
// 安装：sudo apt install libbenchmark-dev  或从源码构建 google/benchmark
#include <benchmark/benchmark.h>

#include "photon_kernel/sandbox/sandbox_pool.hpp"

using namespace photon_kernel::sandbox;

// ---- 基准：从池获取 1000 次 ----
static void BM_PoolAcquire(benchmark::State& state) {
    PoolConfig cfg;
    cfg.min_size = 10;
    cfg.max_size = 50;
    SandboxPool pool(cfg);
    pool.initialize();

    for (auto _ : state) {
        auto instance = pool.acquire(std::chrono::milliseconds(100));
        pool.release(instance);
    }
}
BENCHMARK(BM_PoolAcquire)->Iterations(1000);

// ---- 基准：直接 fork 创建 1000 次 ----
static void BM_ForkCreate(benchmark::State& state) {
    SandboxConfig cfg = SandboxConfig::for_risk_level(RiskLevel::MEDIUM);
    for (auto _ : state) {
        SandboxedExecutor exec(cfg);
        SandboxedTask task;
        task.name = "benchmark";
        task.func = []() { volatile int x = 0; };
        exec.execute_sync(task);
    }
}
BENCHMARK(BM_ForkCreate)->Iterations(1000);

BENCHMARK_MAIN();
