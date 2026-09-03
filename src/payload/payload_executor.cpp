// payload_executor.cpp - 任务载荷执行器实现
#include "photon_kernel/payload/payload_executor.hpp"

#include <sys/wait.h>
#include <sys/resource.h>
#include <unistd.h>
#include <signal.h>
#include <cstring>
#include <cstdlib>
#include <chrono>
#include <thread>
#include <fstream>
#include <sstream>
#include <unordered_map>

namespace photon_kernel::payload {

struct PayloadExecutor::Impl {
    std::unordered_map<std::string, NativeFunc> native_funcs;
};

PayloadExecutor::PayloadExecutor() : impl_(std::make_unique<Impl>()) {}
PayloadExecutor::~PayloadExecutor() = default;

void PayloadExecutor::register_native_func(const std::string& name, NativeFunc func) {
    impl_->native_funcs[name] = func;
}

ExecutionResult PayloadExecutor::execute(ShmChannel& channel) {
    // 等待任务就绪
    if (!channel.wait_for_status(TaskStatus::READY, 5000)) {
        ExecutionResult r;
        r.exit_code = -1;
        r.error = "Timeout waiting for task";
        return r;
    }

    // 读取任务
    size_t payload_size;
    PayloadType type;
    uint64_t task_id;
    uint32_t timeout_ms;
    const uint8_t* payload = channel.read_payload(payload_size, type, task_id, timeout_ms);

    // 标记为运行中
    channel.set_status(TaskStatus::RUNNING);

    // 执行
    ExecutionResult result = execute_payload(payload, payload_size, type, timeout_ms);

    // 写回结果
    std::string result_data = result.output;
    if (!result.error.empty()) {
        if (!result_data.empty()) result_data += "\n";
        result_data += "[stderr] " + result.error;
    }
    channel.write_result(result_data.data(), result_data.size(), result.exit_code);

    return result;
}

ExecutionResult PayloadExecutor::execute_payload(const void* payload, size_t payload_size,
                                                    PayloadType type, uint32_t timeout_ms) {
    if (timeout_ms == 0) timeout_ms = default_timeout_ms_;

    switch (type) {
        case PayloadType::NATIVE:
            return execute_native(static_cast<const uint8_t*>(payload), payload_size, timeout_ms);
        case PayloadType::WASM:
            return execute_wasm(static_cast<const uint8_t*>(payload), payload_size, timeout_ms);
        case PayloadType::PYTHON_BC:
            return execute_python_bc(static_cast<const uint8_t*>(payload), payload_size, timeout_ms);
        case PayloadType::JS_BC:
            return execute_js_bc(static_cast<const uint8_t*>(payload), payload_size, timeout_ms);
        case PayloadType::SHELL:
            return execute_shell(static_cast<const uint8_t*>(payload), payload_size, timeout_ms);
        default: {
            ExecutionResult r;
            r.exit_code = -1;
            r.error = "Unknown payload type";
            return r;
        }
    }
}

ExecutionResult PayloadExecutor::execute_native(const uint8_t* payload, size_t size,
                                                   uint32_t timeout_ms) {
    return execute_with_timeout([&]() -> ExecutionResult {
        ExecutionResult r;
        if (size < sizeof(NativeFunc)) {
            r.exit_code = -1;
            r.error = "Native payload too small";
            return r;
        }
        // 载荷前sizeof(NativeFunc)字节是函数指针, 后面是输入数据
        NativeFunc func = *reinterpret_cast<const NativeFunc*>(payload);
        const uint8_t* input = payload + sizeof(NativeFunc);
        size_t input_size = size - sizeof(NativeFunc);

        // 分配输出缓冲区
        std::vector<uint8_t> output(64 * 1024);
        size_t output_size = 0;

        auto start = std::chrono::steady_clock::now();
        r.exit_code = func(input, input_size, output.data(), output.size(), &output_size);
        auto end = std::chrono::steady_clock::now();
        r.duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
        r.output.assign(reinterpret_cast<const char*>(output.data()), output_size);
        return r;
    }, timeout_ms);
}

ExecutionResult PayloadExecutor::execute_wasm(const uint8_t* payload, size_t size,
                                                 uint32_t timeout_ms) {
    return execute_with_timeout([&]() -> ExecutionResult {
        ExecutionResult r;
        if (!wasm_enabled_) {
            r.exit_code = -1;
            r.error = "WASM execution disabled";
            return r;
        }
        // 简化实现: 将WASM模块写入临时文件, 用wasmtime/wasmer执行
        // 生产环境应使用内嵌WASM运行时(如wasm3)
        std::string tmp_path = "/tmp/photon_wasm_" + std::to_string(getpid()) + ".wasm";
        {
            std::ofstream f(tmp_path, std::ios::binary);
            f.write(reinterpret_cast<const char*>(payload), size);
        }
        std::string cmd = "wasmtime " + tmp_path + " 2>&1 || wasmer " + tmp_path + " 2>&1 || echo 'WASM_RUNTIME_NOT_FOUND'";
        FILE* pipe = popen(cmd.c_str(), "r");
        if (pipe) {
            char buf[4096];
            while (fgets(buf, sizeof(buf), pipe)) r.output += buf;
            int status = pclose(pipe);
            if (WIFEXITED(status)) r.exit_code = WEXITSTATUS(status);
            else r.exit_code = -1;
        }
        unlink(tmp_path.c_str());
        if (r.output.find("WASM_RUNTIME_NOT_FOUND") != std::string::npos) {
            r.exit_code = -1;
            r.error = "No WASM runtime available (install wasmtime or wasmer)";
            r.output.clear();
        }
        return r;
    }, timeout_ms);
}

ExecutionResult PayloadExecutor::execute_python_bc(const uint8_t* payload, size_t size,
                                                      uint32_t timeout_ms) {
    return execute_with_timeout([&]() -> ExecutionResult {
        ExecutionResult r;
        if (!python_enabled_) {
            r.exit_code = -1;
            r.error = "Python execution disabled";
            return r;
        }
        // Python字节码执行: 写入.pyc文件, 用python3执行
        // 生产环境应使用pybind11内嵌解释器, 避免进程创建开销
        std::string tmp_path = "/tmp/photon_pybc_" + std::to_string(getpid()) + ".pyc";
        {
            std::ofstream f(tmp_path, std::ios::binary);
            f.write(reinterpret_cast<const char*>(payload), size);
        }
        // 检测是否为真正的pyc文件(以magic number开头)
        bool is_real_pyc = (size >= 4 && payload[0] == 0x55 && payload[1] == 0x0d &&
                             payload[2] == 0x0d && payload[3] == 0x0a);
        std::string cmd;
        if (is_real_pyc) {
            cmd = "python3 " + tmp_path + " 2>&1";
        } else {
            // 降级为源码, 用python3 -c执行
            // 注意: 源码中可能有特殊字符, 这里简化处理
            std::string source(reinterpret_cast<const char*>(payload), size);
            // 将源码写入临时.py文件
            std::string py_path = tmp_path + ".py";
            {
                std::ofstream f(py_path);
                f << source;
            }
            cmd = "python3 " + py_path + " 2>&1";
        }
        FILE* pipe = popen(cmd.c_str(), "r");
        if (pipe) {
            char buf[4096];
            while (fgets(buf, sizeof(buf), pipe)) r.output += buf;
            int status = pclose(pipe);
            if (WIFEXITED(status)) r.exit_code = WEXITSTATUS(status);
            else r.exit_code = -1;
        }
        unlink(tmp_path.c_str());
        if (!is_real_pyc) {
            unlink((tmp_path + ".py").c_str());
        }
        return r;
    }, timeout_ms);
}

ExecutionResult PayloadExecutor::execute_js_bc(const uint8_t* payload, size_t size,
                                                  uint32_t timeout_ms) {
    return execute_with_timeout([&]() -> ExecutionResult {
        ExecutionResult r;
        if (!js_enabled_) {
            r.exit_code = -1;
            r.error = "JS execution disabled";
            return r;
        }
        // QuickJS字节码执行
        std::string tmp_path = "/tmp/photon_jsbc_" + std::to_string(getpid()) + ".jsc";
        {
            std::ofstream f(tmp_path, std::ios::binary);
            f.write(reinterpret_cast<const char*>(payload), size);
        }
        std::string cmd = "qjs " + tmp_path + " 2>&1 || node -e "
                          "'const fs=require(\"fs\");console.log(\"QuickJS bytecode requires qjs\")' 2>&1";
        FILE* pipe = popen(cmd.c_str(), "r");
        if (pipe) {
            char buf[4096];
            while (fgets(buf, sizeof(buf), pipe)) r.output += buf;
            int status = pclose(pipe);
            if (WIFEXITED(status)) r.exit_code = WEXITSTATUS(status);
            else r.exit_code = -1;
        }
        unlink(tmp_path.c_str());
        return r;
    }, timeout_ms);
}

ExecutionResult PayloadExecutor::execute_shell(const uint8_t* payload, size_t size,
                                                  uint32_t timeout_ms) {
    return execute_with_timeout([&]() -> ExecutionResult {
        ExecutionResult r;
        if (!shell_enabled_) {
            r.exit_code = -1;
            r.error = "Shell execution disabled";
            return r;
        }
        std::string cmd(reinterpret_cast<const char*>(payload), size);
        // 安全检查: 禁止危险命令
        static const std::string dangerous[] = {"rm -rf /", "mkfs", "dd if=", "> /dev/sda"};
        for (const auto& d : dangerous) {
            if (cmd.find(d) != std::string::npos) {
                r.exit_code = -1;
                r.error = "Dangerous command blocked: " + d;
                return r;
            }
        }
        FILE* pipe = popen(cmd.c_str(), "r");
        if (pipe) {
            char buf[4096];
            while (fgets(buf, sizeof(buf), pipe)) r.output += buf;
            int status = pclose(pipe);
            if (WIFEXITED(status)) r.exit_code = WEXITSTATUS(status);
            else r.exit_code = -1;
        }
        return r;
    }, timeout_ms);
}

ExecutionResult PayloadExecutor::execute_with_timeout(std::function<ExecutionResult()> func,
                                                         uint32_t timeout_ms) {
    auto start = std::chrono::steady_clock::now();

    // 创建管道用于子进程传递输出
    int pipefd[2];
    if (pipe(pipefd) < 0) {
        ExecutionResult r;
        r.exit_code = -1;
        r.error = "pipe failed";
        return r;
    }

    // 使用fork实现超时控制
    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        ExecutionResult r;
        r.exit_code = -1;
        r.error = "fork failed";
        return r;
    }

    if (pid == 0) {
        // 子进程
        close(pipefd[0]);  // 关闭读端

        // 设置资源限制
        struct rlimit mem_limit;
        mem_limit.rlim_cur = memory_limit_;
        mem_limit.rlim_max = memory_limit_;
        setrlimit(RLIMIT_AS, &mem_limit);

        struct rlimit cpu_limit;
        cpu_limit.rlim_cur = (timeout_ms + 999) / 1000;
        cpu_limit.rlim_max = cpu_limit.rlim_cur + 1;
        setrlimit(RLIMIT_CPU, &cpu_limit);

        struct rlimit nproc_limit;
        nproc_limit.rlim_cur = 256;
        nproc_limit.rlim_max = 512;
        setrlimit(RLIMIT_NPROC, &nproc_limit);

        // 执行任务
        ExecutionResult r = func();

        // 将输出通过管道写回父进程
        // 格式: [4字节exit_code][4字节output_len][output][4字节error_len][error]
        int32_t exit_code = r.exit_code;
        uint32_t out_len = static_cast<uint32_t>(r.output.size());
        uint32_t err_len = static_cast<uint32_t>(r.error.size());

        write(pipefd[1], &exit_code, sizeof(exit_code));
        write(pipefd[1], &out_len, sizeof(out_len));
        if (out_len > 0) write(pipefd[1], r.output.data(), out_len);
        write(pipefd[1], &err_len, sizeof(err_len));
        if (err_len > 0) write(pipefd[1], r.error.data(), err_len);

        close(pipefd[1]);
        _exit(exit_code & 0xFF);
    }

    // 父进程
    close(pipefd[1]);  // 关闭写端

    ExecutionResult result;
    int status = 0;
    bool timed_out = false;

    // 等待子进程结束或超时
    while (true) {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        if (elapsed >= static_cast<int64_t>(timeout_ms)) {
            kill(pid, SIGKILL);
            timed_out = true;
            break;
        }
        pid_t ret = waitpid(pid, &status, WNOHANG);
        if (ret > 0) break;
        if (ret < 0) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    if (!timed_out) {
        waitpid(pid, &status, 0);
    }

    // 从管道读取子进程输出
    if (!timed_out) {
        int32_t exit_code = 0;
        uint32_t out_len = 0, err_len = 0;

        if (read(pipefd[0], &exit_code, sizeof(exit_code)) == sizeof(exit_code)) {
            result.exit_code = exit_code;
        }
        if (read(pipefd[0], &out_len, sizeof(out_len)) == sizeof(out_len) && out_len > 0) {
            result.output.resize(out_len);
            read(pipefd[0], result.output.data(), out_len);
        }
        if (read(pipefd[0], &err_len, sizeof(err_len)) == sizeof(err_len) && err_len > 0) {
            result.error.resize(err_len);
            read(pipefd[0], result.error.data(), err_len);
        }
    }

    close(pipefd[0]);

    auto end = std::chrono::steady_clock::now();
    result.duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    result.timed_out = timed_out;

    if (timed_out) {
        result.exit_code = -1;
        result.error = "Execution timed out after " + std::to_string(timeout_ms) + "ms";
        result.killed = true;
    } else if (WIFSIGNALED(status)) {
        result.exit_code = -1;
        if (result.error.empty()) {
            result.error = "Killed by signal " + std::to_string(WTERMSIG(status));
        }
        result.killed = true;
    }

    return result;
}

} // namespace photon_kernel::payload
