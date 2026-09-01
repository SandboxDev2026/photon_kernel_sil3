#include <gtest/gtest.h>

#include <cstdio>
#include <string>

#include "photon_kernel/sandbox/code_runner.hpp"

using namespace photon_kernel::sandbox;

TEST(CodeRunnerTest, PythonPrintOk) {
    CodeRunRequest req;
    req.runner = CodeRunner::PYTHON3;
    req.code = "print('hello-from-sandbox')";
    req.timeout = std::chrono::milliseconds(5000);

    auto r = run_user_code(req);
    EXPECT_TRUE(r.success) << r.error;
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_NE(r.output.find("hello-from-sandbox"), std::string::npos);
    EXPECT_GT(r.elapsed_us, 0);
}

TEST(CodeRunnerTest, PythonRuntimeError) {
    CodeRunRequest req;
    req.runner = CodeRunner::PYTHON3;
    req.code = "raise ValueError('boom')";
    req.timeout = std::chrono::milliseconds(5000);

    auto r = run_user_code(req);
    EXPECT_FALSE(r.success);
    EXPECT_EQ(r.exit_code, 1);
}

TEST(CodeRunnerTest, PythonInfiniteLoopTimeout) {
    CodeRunRequest req;
    req.runner = CodeRunner::PYTHON3;
    req.code = "while True: pass";
    req.timeout = std::chrono::milliseconds(500);

    auto t0 = std::chrono::steady_clock::now();
    auto r = run_user_code(req);
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();

    EXPECT_FALSE(r.success);
    EXPECT_NE(r.error.find("timed out"), std::string::npos);
    EXPECT_EQ(r.exit_signal, SIGKILL);
    // 看门狗应基本按时触发（宽松容差）
    EXPECT_GE(elapsed_ms, 400);
    EXPECT_LE(elapsed_ms, 3000);
}

TEST(CodeRunnerTest, ShellEchoOk) {
    CodeRunRequest req;
    req.runner = CodeRunner::SHELL;
    req.code = "echo shell-ok";
    req.timeout = std::chrono::milliseconds(5000);

    auto r = run_user_code(req);
    EXPECT_TRUE(r.success) << r.error;
    EXPECT_NE(r.output.find("shell-ok"), std::string::npos);
}

TEST(CodeRunnerTest, NodeOk) {
    // 若系统无 node 则跳过
    if (::access("/usr/bin/node", F_OK) != 0) {
        GTEST_SKIP() << "/usr/bin/node not installed, skipping";
    }
    CodeRunRequest req;
    req.runner = CodeRunner::NODE;
    req.code = "console.log('node-ok')";
    req.timeout = std::chrono::milliseconds(5000);

    // node 是 V8 多线程解释器，NPROC 需留足线程余量（共享 uid 线程数可能较多）
    auto r = run_user_code(req, /*process_limit=*/256);
    EXPECT_TRUE(r.success) << r.error;
    EXPECT_NE(r.output.find("node-ok"), std::string::npos);
}
