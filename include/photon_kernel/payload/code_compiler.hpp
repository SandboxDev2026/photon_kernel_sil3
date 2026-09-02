// code_compiler.hpp - 宿主机侧代码编译器
// 将用户代码(Python/JS/Shell)预编译为字节码, 通过共享内存注入Worker
#pragma once

#include "photon_kernel/payload/shm_channel.hpp"
#include <string>
#include <vector>
#include <cstdint>

namespace photon_kernel::payload {

// 编译结果
struct CompiledPayload {
    std::vector<uint8_t> bytecode;
    PayloadType type;
    size_t original_size;
    std::string error;
    bool success = false;
};

// 代码编译器(宿主机侧)
class CodeCompiler {
public:
    CodeCompiler();
    ~CodeCompiler();

    // 编译Python源码为字节码(pyc)
    CompiledPayload compile_python(const std::string& source);

    // 编译JS源码为QuickJS字节码
    CompiledPayload compile_javascript(const std::string& source);

    // 编译Shell命令(直接作为文本载荷)
    CompiledPayload compile_shell(const std::string& command);

    // 编译C++源码为共享库(返回.so路径, Worker通过dlopen加载)
    CompiledPayload compile_cpp(const std::string& source,
                                  const std::string& output_dir = "/tmp");

    // 自动检测语言并编译
    CompiledPayload compile_auto(const std::string& code, const std::string& language_hint = "");

    // 将编译后的载荷写入共享内存通道
    bool inject_to_channel(ShmChannel& channel, const CompiledPayload& payload,
                            uint64_t task_id, uint32_t timeout_ms = 10000);

    // 设置Python解释器路径
    void set_python_path(const std::string& path) { python_path_ = path; }
    void set_qjs_path(const std::string& path) { qjs_path_ = path; }
    void set_gcc_path(const std::string& path) { gcc_path_ = path; }

private:
    std::string python_path_ = "python3";
    std::string qjs_path_ = "qjs";
    std::string gcc_path_ = "g++";
};

} // namespace photon_kernel::payload
