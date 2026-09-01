#include <gtest/gtest.h>

#include <string>
#include <chrono>

#include "photon_kernel/sandbox/prewarmed_worker.hpp"

using namespace photon_kernel::sandbox;

namespace {

CodeRunResult run_py(PrewarmedWorker& w, const std::string& code,
                     std::chrono::milliseconds timeout = std::chrono::milliseconds(5000)) {
    CodeRunRequest req;
    req.runner = CodeRunner::PYTHON3;
    req.code = code;
    req.timeout = timeout;
    return w.run(req);
}

} // namespace

// 预 fork worker：一次初始化（seccomp 就绪），可反复复用
TEST(PrewarmedWorkerTest, ForkReadyAndReusable) {
    SandboxConfig cfg = SandboxConfig::for_code_runner();
    PrewarmedWorker worker(cfg);
    EXPECT_TRUE(worker.is_ready());
    EXPECT_TRUE(worker.is_healthy());

    // 任务1：正常执行
    auto r1 = run_py(worker, "print('first')");
    EXPECT_TRUE(r1.success) << r1.error;
    EXPECT_NE(r1.output.find("first"), std::string::npos);

    // 任务2：复用同一 worker（无需重新 fork + 装 seccomp）
    auto r2 = run_py(worker, "print('second')");
    EXPECT_TRUE(r2.success) << r2.error;
    EXPECT_NE(r2.output.find("second"), std::string::npos);

    // 任务3：连续多次
    for (int i = 0; i < 5; ++i) {
        auto r = run_py(worker, "print('loop', " + std::to_string(i) + ")");
        EXPECT_TRUE(r.success) << r.error;
    }
    EXPECT_TRUE(worker.is_healthy());
    worker.shutdown();
}

TEST(PrewarmedWorkerTest, WatchdogKillsInfiniteLoop) {
    SandboxConfig cfg = SandboxConfig::for_code_runner();
    PrewarmedWorker worker(cfg);

    auto r = run_py(worker, "while True: pass", std::chrono::milliseconds(300));
    EXPECT_FALSE(r.success);
    EXPECT_NE(r.error.find("timed out"), std::string::npos);

    // worker 应仍存活可复用
    auto r2 = run_py(worker, "print('alive')");
    EXPECT_TRUE(r2.success) << r2.error;
    worker.shutdown();
}

// seccomp 拦截：worker 内任务进程执行白名单外 syscall（chmod）→ 被杀，worker 本身不受影响
TEST(PrewarmedWorkerTest, SeccompBlocksForbiddenSyscall) {
    SandboxConfig cfg = SandboxConfig::for_code_runner();
    PrewarmedWorker worker(cfg);

    // os.chmod 触发 fchmodat/chmod，均不在 code_runner 白名单 → SECCOMP_RET_KILL_PROCESS
    auto r = run_py(worker, "import os; os.chmod('/tmp/x', 0o644)");
    EXPECT_FALSE(r.success);
    EXPECT_NE(r.exit_signal, 0);  // 被信号杀死（SIGSYS=31 或 SIGKILL）

    // worker 进程本身未被 seccomp 波及，仍可复用
    auto r2 = run_py(worker, "print('worker-still-alive')");
    EXPECT_TRUE(r2.success) << r2.error;
    worker.shutdown();
}
