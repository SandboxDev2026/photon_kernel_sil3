// network_resource_guard.hpp - 网络资源清理守卫
// VM销毁时强制清理tap设备和网络命名空间, 防止资源泄漏
// 这是风险6(网络模型复杂度高)的缓解措施
#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace photon_kernel::sandbox {

// 网络资源类型
enum class NetworkResourceType : uint8_t {
    TAP_DEVICE = 0,      // tap网卡设备
    NETNS = 1,            // 网络命名空间
    VETH_PAIR = 2,        // veth对
    BRIDGE_PORT = 3,      // 网桥端口
    IP_RULE = 4           // iptables规则
};

// 网络资源描述
struct NetworkResource {
    NetworkResourceType type;
    std::string name;           // 资源名称(如tap设备名、netns名)
    std::string vm_id;          // 关联的VM ID
    uint64_t created_at = 0;    // 创建时间戳
    bool cleaned = false;        // 是否已清理
};

// 清理结果
struct CleanupResult {
    bool success = false;
    int attempts = 0;            // 尝试次数
    std::string error;           // 错误信息
    uint64_t duration_ms = 0;    // 清理耗时
};

// 网络资源清理守卫
class NetworkResourceGuard {
public:
    NetworkResourceGuard();
    ~NetworkResourceGuard();

    // 注册资源(创建时调用)
    void register_resource(const NetworkResource& resource);

    // 清理单个VM的所有网络资源(VM销毁时调用)
    // 会重试max_attempts次, 确保资源被清理
    CleanupResult cleanup_vm_resources(const std::string& vm_id, int max_attempts = 3);

    // 清理所有已注册资源
    CleanupResult cleanup_all(int max_attempts = 3);

    // 检查资源是否存在
    bool resource_exists(const NetworkResource& resource) const;

    // 获取泄漏的资源数量(已创建但未清理)
    size_t leaked_count() const;

    // 获取所有泄漏的资源
    std::vector<NetworkResource> get_leaked_resources() const;

    // 强制清理单个资源(底层命令)
    bool force_cleanup(const NetworkResource& resource);

    // 配置: 清理超时(毫秒)
    void set_cleanup_timeout_ms(uint32_t ms) { cleanup_timeout_ms_ = ms; }
    uint32_t cleanup_timeout_ms() const { return cleanup_timeout_ms_; }

    // 统计
    uint64_t total_registered() const { return total_registered_; }
    uint64_t total_cleaned() const { return total_cleaned_; }
    uint64_t total_failures() const { return total_failures_; }

private:
    std::vector<NetworkResource> resources_;
    uint32_t cleanup_timeout_ms_ = 5000;  // 默认5秒超时
    uint64_t total_registered_ = 0;
    uint64_t total_cleaned_ = 0;
    uint64_t total_failures_ = 0;

    // 底层清理命令
    bool cleanup_tap(const std::string& name);
    bool cleanup_netns(const std::string& name);
    bool cleanup_veth(const std::string& name);
    bool cleanup_bridge_port(const std::string& bridge, const std::string& port);

    // 执行系统命令(带超时)
    int execute_command(const std::string& cmd, uint32_t timeout_ms) const;
};

} // namespace photon_kernel::sandbox
