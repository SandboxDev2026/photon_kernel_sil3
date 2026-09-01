#include <gtest/gtest.h>

#include <chrono>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "photon_kernel/sandbox/sandbox_pool_v2.hpp"

using namespace photon_kernel::sandbox;

TEST(PoolV2Test, PreforkInitializeAndExecute) {
    PoolV2Config cfg;
    cfg.min_size = 3;
    cfg.max_size = 10;

    auto t0 = std::chrono::steady_clock::now();
    SandboxPoolV2 pool(cfg);
    pool.initialize();
    auto init_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();

    // 预热阶段一次性 fork + seccomp；这里只是初始化耗时（可能几十 ms，属一次性成本）
    auto st = pool.get_status();
    EXPECT_EQ(st.total, 3u);
    EXPECT_EQ(st.idle, 3u);
    EXPECT_EQ(st.busy, 0u);

    // 任务执行：从池复用已就绪 worker，延迟应在毫秒级
    auto t1 = std::chrono::steady_clock::now();
    CodeRunRequest req;
    req.runner = CodeRunner::PYTHON3;
    req.code = "print('pool-ok')";
    req.timeout = std::chrono::milliseconds(5000);
    auto r = pool.execute(req);
    auto task_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t1).count();

    EXPECT_TRUE(r.success) << r.error;
    EXPECT_NE(r.output.find("pool-ok"), std::string::npos);

    // 池状态应恢复（worker 归还）
    st = pool.get_status();
    EXPECT_EQ(st.idle, 3u);
    EXPECT_EQ(st.busy, 0u);

    // 并发执行：多个任务交错（池有 3 个 worker）
    CodeRunRequest req2 = req;
    req2.code = "import time; time.sleep(0.05); print('concurrent')";
    auto r2 = pool.execute(req2);
    EXPECT_TRUE(r2.success) << r2.error;

    pool.shutdown();
    std::cout << "[PoolV2] init=" << init_ms << "ms, single-task=" << task_ms << "ms\n";
}

TEST(PoolV2Test, DynamicScaleUp) {
    PoolV2Config cfg;
    cfg.min_size = 1;
    cfg.max_size = 4;

    SandboxPoolV2 pool(cfg);
    pool.initialize();

    // 3 个线程并发执行：池最小 1 个 worker，需动态扩容
    std::vector<CodeRunResult> results(3);
    std::vector<std::thread> threads;
    for (int i = 0; i < 3; ++i) {
        threads.emplace_back([&pool, &results, i] {
            CodeRunRequest req;
            req.runner = CodeRunner::PYTHON3;
            req.code = "import time; time.sleep(0.1); print('ok')";
            req.timeout = std::chrono::milliseconds(5000);
            results[static_cast<size_t>(i)] = pool.execute(req);
        });
    }
    for (auto& t : threads) t.join();
    for (auto& r : results) {
        EXPECT_TRUE(r.success) << r.error;
    }
    auto st = pool.get_status();
    EXPECT_GE(st.total, 2u);   // 动态扩容（至少扩到并发数）
    pool.shutdown();
}
