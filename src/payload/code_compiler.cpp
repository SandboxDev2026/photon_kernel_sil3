// code_compiler.cpp - 宿主机侧代码编译器实现
#include "photon_kernel/payload/code_compiler.hpp"

#include <fstream>
#include <sstream>
#include <cstdlib>
#include <unistd.h>
#include <sys/wait.h>

namespace photon_kernel::payload {

CodeCompiler::CodeCompiler() = default;
CodeCompiler::~CodeCompiler() = default;

CompiledPayload CodeCompiler::compile_python(const std::string& source) {
    CompiledPayload result;
    result.type = PayloadType::PYTHON_BC;
    result.original_size = source.size();

    // 写入临时.py文件
    std::string src_path = "/tmp/photon_compile_" + std::to_string(getpid()) + ".py";
    std::string pyc_path = src_path + "c";
    {
        std::ofstream f(src_path);
        f << source;
    }

    // 用python3 -m py_compile编译
    std::string cmd = python_path_ + " -m py_compile " + src_path + " 2>&1";
    FILE* pipe = popen(cmd.c_str(), "r");
    std::string err;
    if (pipe) {
        char buf[1024];
        while (fgets(buf, sizeof(buf), pipe)) err += buf;
        pclose(pipe);
    }

    // 读取pyc文件(python3会生成__pycache__/xxx.cpython-XX.pyc)
    std::string pycache_path = "/tmp/__pycache__/photon_compile_" + std::to_string(getpid()) + ".cpython-";
    // 尝试多种可能的pyc路径
    std::string actual_pyc = pyc_path;
    if (access(actual_pyc.c_str(), F_OK) != 0) {
        // 尝试__pycache__目录
        std::string ver = "312";  // 默认python3.12
        actual_pyc = "/tmp/__pycache__/photon_compile_" + std::to_string(getpid()) + ".cpython-" + ver + ".pyc";
    }

    std::ifstream pyc_file(actual_pyc, std::ios::binary);
    if (pyc_file) {
        result.bytecode.assign((std::istreambuf_iterator<char>(pyc_file)),
                                std::istreambuf_iterator<char>());
        result.success = !result.bytecode.empty();
    } else {
        // 降级: 直接返回源码作为文本(Worker会用python3执行)
        result.bytecode.assign(source.begin(), source.end());
        result.success = true;  // 降级也算成功
        result.error = "py_compile failed, falling back to source execution: " + err;
    }

    unlink(src_path.c_str());
    unlink(pyc_path.c_str());
    unlink(actual_pyc.c_str());
    return result;
}

CompiledPayload CodeCompiler::compile_javascript(const std::string& source) {
    CompiledPayload result;
    result.type = PayloadType::JS_BC;
    result.original_size = source.size();

    // 写入临时.js文件
    std::string src_path = "/tmp/photon_compile_" + std::to_string(getpid()) + ".js";
    std::string bc_path = src_path + ".jsc";
    {
        std::ofstream f(src_path);
        f << source;
    }

    // 用qjs -c编译为字节码
    std::string cmd = qjs_path_ + " -c -o " + bc_path + " " + src_path + " 2>&1";
    FILE* pipe = popen(cmd.c_str(), "r");
    std::string err;
    if (pipe) {
        char buf[1024];
        while (fgets(buf, sizeof(buf), pipe)) err += buf;
        pclose(pipe);
    }

    std::ifstream bc_file(bc_path, std::ios::binary);
    if (bc_file) {
        result.bytecode.assign((std::istreambuf_iterator<char>(bc_file)),
                                std::istreambuf_iterator<char>());
        result.success = !result.bytecode.empty();
    } else {
        // 降级: 直接返回源码
        result.bytecode.assign(source.begin(), source.end());
        result.success = true;
        result.error = "qjs compile failed, falling back to source execution: " + err;
    }

    unlink(src_path.c_str());
    unlink(bc_path.c_str());
    return result;
}

CompiledPayload CodeCompiler::compile_shell(const std::string& command) {
    CompiledPayload result;
    result.type = PayloadType::SHELL;
    result.original_size = command.size();
    result.bytecode.assign(command.begin(), command.end());
    result.success = true;
    return result;
}

CompiledPayload CodeCompiler::compile_cpp(const std::string& source,
                                             const std::string& output_dir) {
    CompiledPayload result;
    result.type = PayloadType::NATIVE;
    result.original_size = source.size();

    std::string src_path = output_dir + "/photon_compile_" + std::to_string(getpid()) + ".cpp";
    std::string so_path = output_dir + "/photon_compile_" + std::to_string(getpid()) + ".so";
    {
        std::ofstream f(src_path);
        f << source;
    }

    std::string cmd = gcc_path_ + " -shared -fPIC -O2 -o " + so_path + " " + src_path + " 2>&1";
    FILE* pipe = popen(cmd.c_str(), "r");
    std::string err;
    if (pipe) {
        char buf[1024];
        while (fgets(buf, sizeof(buf), pipe)) err += buf;
        pclose(pipe);
    }

    std::ifstream so_file(so_path, std::ios::binary);
    if (so_file) {
        result.bytecode.assign((std::istreambuf_iterator<char>(so_file)),
                                std::istreambuf_iterator<char>());
        result.success = !result.bytecode.empty();
    } else {
        result.success = false;
        result.error = "C++ compile failed: " + err;
    }

    unlink(src_path.c_str());
    unlink(so_path.c_str());
    return result;
}

CompiledPayload CodeCompiler::compile_auto(const std::string& code,
                                              const std::string& language_hint) {
    if (language_hint == "python" || language_hint == "py") {
        return compile_python(code);
    } else if (language_hint == "javascript" || language_hint == "js") {
        return compile_javascript(code);
    } else if (language_hint == "shell" || language_hint == "bash" || language_hint == "sh") {
        return compile_shell(code);
    } else if (language_hint == "cpp" || language_hint == "c++") {
        return compile_cpp(code);
    }

    // 自动检测
    if (code.find("def ") != std::string::npos || code.find("import ") != std::string::npos) {
        return compile_python(code);
    } else if (code.find("function ") != std::string::npos || code.find("console.log") != std::string::npos) {
        return compile_javascript(code);
    } else if (code.find("#!/bin/") != std::string::npos || code.find("echo ") != std::string::npos) {
        return compile_shell(code);
    }

    // 默认作为shell
    return compile_shell(code);
}

bool CodeCompiler::inject_to_channel(ShmChannel& channel, const CompiledPayload& payload,
                                       uint64_t task_id, uint32_t timeout_ms) {
    if (!payload.success) return false;
    channel.write_payload(payload.bytecode.data(), payload.bytecode.size(),
                          payload.type, task_id, timeout_ms);
    return true;
}

} // namespace photon_kernel::payload
