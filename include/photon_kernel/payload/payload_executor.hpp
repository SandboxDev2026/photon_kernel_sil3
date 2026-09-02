// payload_executor.hpp - 任务载荷执行器
// Worker进程从共享内存读取任务载荷, 执行, 将结果写回共享内存
// 支持: C++原生函数指针、WASM模块、Python字节码、JS字节码、Shell命令
#pragma once

#include "photon_kernel/payload/shm_channel.hpp"
#include <cstdint>
#include <cstddef>
#include <string>
#include <functional>
#include <memory>

namespace photon_kernel::payload {

// 执行结果
struct ExecutionResult {
    int exit_code = 0;
    std::string output;      // stdout输出
    std::string error;       // stderr输出
    uint64_t duration_ns = 0;
    bool timed_out = false;
    bool killed = false;
};

// 原生函数签名(用于C++ lambda注入)
using NativeFunc = int (*)(const uint8_t* input, size_t input_size,
                            uint8_t* output, size_t output_capacity,
                            size_t* output_size);

// 载荷执行器
class PayloadExecutor {
public:
    PayloadExecutor();
    ~PayloadExecutor();

    // 执行共享内存中的任务(Worker侧主循环调用)
    ExecutionResult execute(ShmChannel& channel);

    // 执行单个载荷(直接调用, 用于测试)
    ExecutionResult execute_payload(const void* payload, size_t payload_size,
                                     PayloadType type, uint32_t timeout_ms);

    // 设置资源限制
    void set_memory_limit(size_t bytes) { memory_limit_ = bytes; }
    void set_cpu_limit(int cpus) { cpu_limit_ = cpus; }
    void set_default_timeout(uint32_t ms) { default_timeout_ms_ = ms; }

    // 注册原生函数(用于C++ lambda注入)
    void register_native_func(const std::string& name, NativeFunc func);

    // 启用/禁用解释器(Python/JS)
    void set_python_enabled(bool enabled) { python_enabled_ = enabled; }
    void set_js_enabled(bool enabled) { js_enabled_ = enabled; }
    void set_wasm_enabled(bool enabled) { wasm_enabled_ = enabled; }
    void set_shell_enabled(bool enabled) { shell_enabled_ = enabled; }

private:
    ExecutionResult execute_native(const uint8_t* payload, size_t size, uint32_t timeout_ms);
    ExecutionResult execute_wasm(const uint8_t* payload, size_t size, uint32_t timeout_ms);
    ExecutionResult execute_python_bc(const uint8_t* payload, size_t size, uint32_t timeout_ms);
    ExecutionResult execute_js_bc(const uint8_t* payload, size_t size, uint32_t timeout_ms);
    ExecutionResult execute_shell(const uint8_t* payload, size_t size, uint32_t timeout_ms);

    // 带超时的执行(使用fork+waitpid+SIGKILL)
    ExecutionResult execute_with_timeout(std::function<ExecutionResult()> func,
                                           uint32_t timeout_ms);

    size_t memory_limit_ = 128 * 1024 * 1024;  // 128MB
    int cpu_limit_ = 1;
    uint32_t default_timeout_ms_ = 10000;  // 10秒
    bool python_enabled_ = true;
    bool js_enabled_ = true;
    bool wasm_enabled_ = true;
    bool shell_enabled_ = true;

    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace photon_kernel::payload
