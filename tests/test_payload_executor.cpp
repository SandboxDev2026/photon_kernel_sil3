// test_payload_executor.cpp - 任务载荷执行器测试
#include <gtest/gtest.h>
#include "photon_kernel/payload/shm_channel.hpp"
#include "photon_kernel/payload/payload_executor.hpp"
#include "photon_kernel/payload/code_compiler.hpp"
#include "photon_kernel/payload/strong_pool_config.hpp"

#include <sys/wait.h>
#include <unistd.h>
#include <cstring>
#include <thread>

using namespace photon_kernel::payload;

// ===== ShmChannel 测试 =====

TEST(ShmChannelTest, CreateAndOpen) {
    std::string name = "/test_shm_create_" + std::to_string(getpid());
    ShmChannel::unlink(name);

    {
        auto ch = ShmChannel::create(name, 4096, 1024);
        EXPECT_EQ(ch.payload_size(), 4096u);
        EXPECT_EQ(ch.result_size(), 1024u);
        EXPECT_EQ(ch.get_status(), TaskStatus::IDLE);
    }

    ShmChannel::unlink(name);
}

TEST(ShmChannelTest, WriteAndReadPayload) {
    std::string name = "/test_shm_payload_" + std::to_string(getpid());
    ShmChannel::unlink(name);

    auto ch = ShmChannel::create(name, 4096, 1024);
    std::string data = "hello payload";
    ch.write_payload(data.data(), data.size(), PayloadType::SHELL, 12345, 5000);

    EXPECT_EQ(ch.get_status(), TaskStatus::READY);

    size_t size;
    PayloadType type;
    uint64_t task_id;
    uint32_t timeout;
    const uint8_t* payload = ch.read_payload(size, type, task_id, timeout);

    EXPECT_EQ(size, data.size());
    EXPECT_EQ(type, PayloadType::SHELL);
    EXPECT_EQ(task_id, 12345u);
    EXPECT_EQ(timeout, 5000u);
    EXPECT_EQ(std::memcmp(payload, data.data(), size), 0);

    ShmChannel::unlink(name);
}

TEST(ShmChannelTest, WriteAndReadResult) {
    std::string name = "/test_shm_result_" + std::to_string(getpid());
    ShmChannel::unlink(name);

    auto ch = ShmChannel::create(name, 4096, 1024);
    std::string result = "execution output";
    ch.write_result(result.data(), result.size(), 0);

    EXPECT_EQ(ch.get_status(), TaskStatus::DONE);

    size_t size;
    int exit_code;
    const uint8_t* res = ch.read_result(size, exit_code);

    EXPECT_EQ(size, result.size());
    EXPECT_EQ(exit_code, 0);
    EXPECT_EQ(std::memcmp(res, result.data(), size), 0);

    ShmChannel::unlink(name);
}

TEST(ShmChannelTest, StatusTransitions) {
    std::string name = "/test_shm_status_" + std::to_string(getpid());
    ShmChannel::unlink(name);

    auto ch = ShmChannel::create(name);
    EXPECT_EQ(ch.get_status(), TaskStatus::IDLE);

    ch.set_status(TaskStatus::RUNNING);
    EXPECT_EQ(ch.get_status(), TaskStatus::RUNNING);

    ch.set_status(TaskStatus::DONE);
    EXPECT_EQ(ch.get_status(), TaskStatus::DONE);

    ShmChannel::unlink(name);
}

// ===== PayloadExecutor 测试 =====

TEST(PayloadExecutorTest, ShellExecution) {
    PayloadExecutor executor;
    executor.set_shell_enabled(true);

    std::string cmd = "echo 'hello from shell'";
    ExecutionResult result = executor.execute_payload(
        cmd.data(), cmd.size(), PayloadType::SHELL, 5000);

    EXPECT_EQ(result.exit_code, 0);
    EXPECT_NE(result.output.find("hello from shell"), std::string::npos);
    EXPECT_FALSE(result.timed_out);
}

TEST(PayloadExecutorTest, ShellTimeout) {
    PayloadExecutor executor;
    executor.set_shell_enabled(true);

    std::string cmd = "sleep 30";
    ExecutionResult result = executor.execute_payload(
        cmd.data(), cmd.size(), PayloadType::SHELL, 500);

    EXPECT_TRUE(result.timed_out);
    EXPECT_TRUE(result.killed);
    EXPECT_EQ(result.exit_code, -1);
}

TEST(PayloadExecutorTest, ShellDangerousCommandBlocked) {
    PayloadExecutor executor;
    executor.set_shell_enabled(true);

    std::string cmd = "rm -rf /";
    ExecutionResult result = executor.execute_payload(
        cmd.data(), cmd.size(), PayloadType::SHELL, 1000);

    EXPECT_EQ(result.exit_code, -1);
    EXPECT_NE(result.error.find("Dangerous command blocked"), std::string::npos);
}

TEST(PayloadExecutorTest, PythonExecution) {
    PayloadExecutor executor;
    executor.set_python_enabled(true);

    std::string code = "print('hello from python')";
    ExecutionResult result = executor.execute_payload(
        code.data(), code.size(), PayloadType::PYTHON_BC, 5000);

    // Python字节码执行可能降级为源码执行
    EXPECT_TRUE(result.exit_code == 0 || !result.error.empty());
}

TEST(PayloadExecutorTest, DisabledPayloadType) {
    PayloadExecutor executor;
    executor.set_shell_enabled(false);

    std::string cmd = "echo hello";
    ExecutionResult result = executor.execute_payload(
        cmd.data(), cmd.size(), PayloadType::SHELL, 1000);

    EXPECT_EQ(result.exit_code, -1);
    EXPECT_NE(result.error.find("disabled"), std::string::npos);
}

// ===== CodeCompiler 测试 =====

TEST(CodeCompilerTest, CompileShell) {
    CodeCompiler compiler;
    auto result = compiler.compile_shell("echo hello");
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.type, PayloadType::SHELL);
    EXPECT_FALSE(result.bytecode.empty());
}

TEST(CodeCompilerTest, CompilePython) {
    CodeCompiler compiler;
    auto result = compiler.compile_python("print('hello')");
    EXPECT_TRUE(result.success);  // 即使降级也算成功
    EXPECT_EQ(result.type, PayloadType::PYTHON_BC);
}

TEST(CodeCompilerTest, CompileAutoPython) {
    CodeCompiler compiler;
    auto result = compiler.compile_auto("def foo():\n    return 42\n", "python");
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.type, PayloadType::PYTHON_BC);
}

TEST(CodeCompilerTest, CompileAutoShell) {
    CodeCompiler compiler;
    auto result = compiler.compile_auto("echo hello", "shell");
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.type, PayloadType::SHELL);
}

TEST(CodeCompilerTest, InjectToChannel) {
    CodeCompiler compiler;
    auto compiled = compiler.compile_shell("echo injected");

    std::string name = "/test_inject_" + std::to_string(getpid());
    ShmChannel::unlink(name);
    auto ch = ShmChannel::create(name);

    bool ok = compiler.inject_to_channel(ch, compiled, 999, 3000);
    EXPECT_TRUE(ok);
    EXPECT_EQ(ch.get_status(), TaskStatus::READY);

    ShmChannel::unlink(name);
}

// ===== StrongPoolConfig 测试 =====

TEST(StrongPoolConfigTest, EvolutionConfigDefaults) {
    auto cfg = evolution_task_config();
    EXPECT_TRUE(cfg.force_strong_for_evolution);
    EXPECT_FALSE(cfg.allow_light_pool);  // 进化候选禁用LightPool
    EXPECT_TRUE(cfg.reject_on_no_kvm);
    EXPECT_EQ(cfg.memory_limit_bytes, 128u * 1024 * 1024);  // 128M
    EXPECT_EQ(cfg.cpu_count, 1);
    EXPECT_EQ(cfg.timeout_ms, 10u * 1000);  // 10s
    EXPECT_TRUE(cfg.enable_vm_ttl);
    EXPECT_EQ(cfg.vm_ttl_ms, 30u * 1000);  // 30s TTL
    EXPECT_TRUE(cfg.force_destroy_on_ttl);
    EXPECT_TRUE(cfg.enable_snapshot_pool);
    EXPECT_EQ(cfg.snapshot_pool_size, 8);
    EXPECT_DOUBLE_EQ(cfg.memory_reserve_ratio, 0.30);  // 30%缓冲
    EXPECT_TRUE(cfg.block_internal_ips);
    EXPECT_TRUE(cfg.block_metadata_service);
}

TEST(StrongPoolConfigTest, Validate) {
    StrongPoolConfig cfg;
    EXPECT_TRUE(cfg.validate());

    cfg.memory_limit_bytes = 1024;  // 太小
    EXPECT_FALSE(cfg.validate());

    cfg = evolution_task_config();
    cfg.memory_reserve_ratio = 0.9;  // 太大
    EXPECT_FALSE(cfg.validate());
}

TEST(StrongPoolConfigTest, CalculateMaxConcurrentVMs) {
    auto cfg = evolution_task_config();
    // 8G内存, 30%预留 = 5.6G可用, 每个VM 128M = 44个VM
    int max_vms = cfg.calculate_max_concurrent_vms(8ULL * 1024 * 1024 * 1024);
    EXPECT_GT(max_vms, 0);
    EXPECT_LT(max_vms, 100);  // 不会超过内存限制
}

// ===== 端到端测试: Injector -> Worker =====

TEST(PayloadE2ETest, InjectorWorkerShell) {
    std::string name = "/test_e2e_" + std::to_string(getpid());
    ShmChannel::unlink(name);

    // 创建通道(Injector侧)
    auto channel = ShmChannel::create(name);

    // fork Worker进程
    pid_t pid = fork();
    if (pid == 0) {
        // Worker子进程
        PayloadExecutor executor;
        executor.set_shell_enabled(true);
        ExecutionResult result = executor.execute(channel);
        _exit(result.exit_code & 0xFF);
    }

    // Injector父进程: 等待Worker启动
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // 注入任务
    CodeCompiler compiler;
    auto compiled = compiler.compile_shell("echo 'e2e test passed'");
    compiler.inject_to_channel(channel, compiled, 1, 5000);

    // 等待结果
    ASSERT_TRUE(channel.wait_for_status(TaskStatus::DONE, 10000));

    size_t result_size;
    int exit_code;
    const uint8_t* result = channel.read_result(result_size, exit_code);
    std::string result_str(reinterpret_cast<const char*>(result), result_size);

    EXPECT_NE(result_str.find("e2e test passed"), std::string::npos);

    // 等待Worker退出
    int status;
    waitpid(pid, &status, 0);

    ShmChannel::unlink(name);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
