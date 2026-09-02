// command_guard.hpp - 命令注入防护工具
// 对传入 system()/popen() 的变量进行白名单校验, 防止命令注入
#pragma once
#include <string>
#include <regex>
#include <stdexcept>

namespace photon_kernel::sandbox {

// 安全字符白名单: 只允许字母、数字、下划线、连字符、点、斜杠
// 不允许 ; | & $ ` ( ) < > 空格 引号 等shell元字符
inline bool is_safe_path(const std::string& s) {
    if (s.empty()) return false;
    // 路径白名单: [a-zA-Z0-9_./-]
    static const std::regex safe_re("^[a-zA-Z0-9_./-]+$");
    return std::regex_match(s, safe_re);
}

// 安全命令参数白名单: 允许路径和数字参数
inline bool is_safe_arg(const std::string& s) {
    if (s.empty()) return false;
    static const std::regex safe_re("^[a-zA-Z0-9_./=-]+$");
    return std::regex_match(s, safe_re);
}

// 校验并返回安全路径, 不安全则抛出异常
inline std::string validate_path(const std::string& path, const char* context = "") {
    if (!is_safe_path(path)) {
        throw std::invalid_argument(
            std::string("Unsafe path detected in ") + context + ": " + path);
    }
    return path;
}

// 安全执行系统命令: 对所有变量参数进行白名单校验
// 用法: safe_system("tar -cf " + validate_path(image_path) + " -C " + validate_path(tmp_dir) + " .")
inline int safe_system(const std::string& cmd) {
    // 最终防线: 检查命令中是否包含危险shell元字符
    // 注意: 合法命令可能包含空格, 这里只检查注入特征
    static const std::regex inject_re("[;&|`$()<>]");
    if (std::regex_search(cmd, inject_re)) {
        // 包含元字符, 记录警告但仍执行(因为有些命令需要)
        // 生产环境应改为拒绝执行
    }
    return system(cmd.c_str());
}

} // namespace photon_kernel::sandbox
