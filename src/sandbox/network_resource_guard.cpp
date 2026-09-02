// network_resource_guard.cpp - 网络资源清理守卫实现
#include "photon_kernel/sandbox/network_resource_guard.hpp"

#include <iostream>
#include <sstream>
#include <chrono>
#include <thread>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>

namespace photon_kernel::sandbox {

NetworkResourceGuard::NetworkResourceGuard() = default;
NetworkResourceGuard::~NetworkResourceGuard() {
    // 析构时尝试清理所有泄漏的资源
    if (leaked_count() > 0) {
        std::cerr << "[NETWORK_GUARD] Destructor: cleaning up " << leaked_count()
                  << " leaked network resources" << std::endl;
        cleanup_all();
    }
}

void NetworkResourceGuard::register_resource(const NetworkResource& resource) {
    resources_.push_back(resource);
    total_registered_++;
}

CleanupResult NetworkResourceGuard::cleanup_vm_resources(const std::string& vm_id, int max_attempts) {
    CleanupResult result;
    result.success = true;
    auto start = std::chrono::steady_clock::now();

    for (int attempt = 0; attempt < max_attempts; attempt++) {
        result.attempts = attempt + 1;
        bool all_cleaned = true;

        for (auto& res : resources_) {
            if (res.vm_id == vm_id && !res.cleaned) {
                if (force_cleanup(res)) {
                    res.cleaned = true;
                    total_cleaned_++;
                } else {
                    all_cleaned = false;
                }
            }
        }

        if (all_cleaned) break;

        // 重试前等待
        if (attempt < max_attempts - 1) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100 * (attempt + 1)));
        }
    }

    // 检查是否还有未清理的资源
    for (const auto& res : resources_) {
        if (res.vm_id == vm_id && !res.cleaned) {
            result.success = false;
            result.error = "Failed to clean resource: " + res.name;
            total_failures_++;
        }
    }

    auto end = std::chrono::steady_clock::now();
    result.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    if (!result.success) {
        std::cerr << "[NETWORK_GUARD] WARNING: Failed to clean VM " << vm_id
                  << " resources after " << result.attempts << " attempts" << std::endl;
    }

    return result;
}

CleanupResult NetworkResourceGuard::cleanup_all(int max_attempts) {
    CleanupResult result;
    result.success = true;

    for (const auto& res : resources_) {
        if (!res.cleaned) {
            auto vm_result = cleanup_vm_resources(res.vm_id, max_attempts);
            if (!vm_result.success) {
                result.success = false;
                result.error = vm_result.error;
            }
        }
    }

    return result;
}

bool NetworkResourceGuard::resource_exists(const NetworkResource& resource) const {
    switch (resource.type) {
        case NetworkResourceType::TAP_DEVICE: {
            std::string cmd = "ip link show " + resource.name + " >/dev/null 2>&1";
            return execute_command(cmd, 1000) == 0;
        }
        case NetworkResourceType::NETNS: {
            std::string cmd = "ip netns list | grep -q " + resource.name;
            return execute_command(cmd, 1000) == 0;
        }
        default:
            return false;
    }
}

size_t NetworkResourceGuard::leaked_count() const {
    size_t count = 0;
    for (const auto& res : resources_) {
        if (!res.cleaned) count++;
    }
    return count;
}

std::vector<NetworkResource> NetworkResourceGuard::get_leaked_resources() const {
    std::vector<NetworkResource> leaked;
    for (const auto& res : resources_) {
        if (!res.cleaned) leaked.push_back(res);
    }
    return leaked;
}

bool NetworkResourceGuard::force_cleanup(const NetworkResource& resource) {
    // 先检查资源是否存在, 不存在则视为清理成功
    if (!resource_exists(resource)) {
        return true;
    }
    switch (resource.type) {
        case NetworkResourceType::TAP_DEVICE:
            return cleanup_tap(resource.name);
        case NetworkResourceType::NETNS:
            return cleanup_netns(resource.name);
        case NetworkResourceType::VETH_PAIR:
            return cleanup_veth(resource.name);
        case NetworkResourceType::BRIDGE_PORT:
            return cleanup_bridge_port("", resource.name);
        default:
            return false;
    }
}

bool NetworkResourceGuard::cleanup_tap(const std::string& name) {
    // 先设置down, 再删除
    std::string cmd1 = "ip link set " + name + " down 2>/dev/null";
    execute_command(cmd1, cleanup_timeout_ms_);
    std::string cmd2 = "ip tuntap del mode tap " + name + " 2>/dev/null || ip link del " + name + " 2>/dev/null";
    return execute_command(cmd2, cleanup_timeout_ms_) == 0;
}

bool NetworkResourceGuard::cleanup_netns(const std::string& name) {
    std::string cmd = "ip netns del " + name + " 2>/dev/null";
    return execute_command(cmd, cleanup_timeout_ms_) == 0;
}

bool NetworkResourceGuard::cleanup_veth(const std::string& name) {
    std::string cmd = "ip link del " + name + " 2>/dev/null";
    return execute_command(cmd, cleanup_timeout_ms_) == 0;
}

bool NetworkResourceGuard::cleanup_bridge_port(const std::string& bridge, const std::string& port) {
    std::string cmd;
    if (!bridge.empty()) {
        cmd = "ip link set " + port + " nomaster 2>/dev/null";
    } else {
        cmd = "ip link del " + port + " 2>/dev/null";
    }
    return execute_command(cmd, cleanup_timeout_ms_) == 0;
}

int NetworkResourceGuard::execute_command(const std::string& cmd, uint32_t timeout_ms) const {
    pid_t pid = fork();
    if (pid < 0) return -1;

    if (pid == 0) {
        // 子进程: 执行命令
        execl("/bin/sh", "sh", "-c", cmd.c_str(), nullptr);
        _exit(127);
    }

    // 父进程: 等待超时
    int status;
    auto start = std::chrono::steady_clock::now();

    while (true) {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        if (elapsed >= static_cast<int64_t>(timeout_ms)) {
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            return -1;  // 超时
        }
        pid_t ret = waitpid(pid, &status, WNOHANG);
        if (ret > 0) {
            if (WIFEXITED(status)) return WEXITSTATUS(status);
            return -1;
        }
        if (ret < 0) return -1;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

} // namespace photon_kernel::sandbox
