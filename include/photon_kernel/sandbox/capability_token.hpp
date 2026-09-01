#ifndef PHOTON_KERNEL_SANDBOX_CAPABILITY_TOKEN_HPP
#define PHOTON_KERNEL_SANDBOX_CAPABILITY_TOKEN_HPP
// CapabilityToken —— 借鉴鸿蒙 AT-Token 票据权限模型。
// 传统 seccomp/rlimit 是静态写死、加载后不可修改；
// CapabilityToken 是票据式权限：临时授予、带 HMAC 签名防篡改、运行时可撤销。
//
// 每个沙盒实例分配一个票据，包含：
//   - 允许执行的程序路径白名单
//   - 允许出站的网络 CIDR/端口
//   - 允许访问的文件路径列表
//   - CPU/内存/fork 限制
//   - 过期时间
// 所有外部资源访问必须经过控制器校验票据，票据可随时 RecallCapability 撤销。
#include <string>
#include <vector>
#include <chrono>
#include <cstdint>
#include <optional>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
namespace photon_kernel {
namespace sandbox {
// 网络访问规则
struct NetworkRule {
    std::string cidr;        // e.g. "10.0.0.0/8", "0.0.0.0/0"
    uint16_t port_min = 1;
    uint16_t port_max = 65535;
    std::string protocol;    // "tcp", "udp", "icmp"
};
// 文件访问规则
struct PathRule {
    std::string path;
    bool read = true;
    bool write = false;
    bool execute = false;
};
// 能力位（可单独撤销）
enum class Capability : uint32_t {
    NONE        = 0,
    EXEC        = 1 << 0,   // 允许执行程序
    NETWORK     = 1 << 1,   // 允许出站网络
    FILE_READ   = 1 << 2,   // 允许读文件
    FILE_WRITE  = 1 << 3,   // 允许写文件
    FORK        = 1 << 4,   // 允许 fork 子进程
    SOCKET      = 1 << 5,   // 允许创建 socket
    ALL         = 0xFFFFFFFF,
};
inline Capability operator|(Capability a, Capability b) {
    return static_cast<Capability>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}
inline Capability operator&(Capability a, Capability b) {
    return static_cast<Capability>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}
inline bool has_capability(Capability caps, Capability target) {
    return (static_cast<uint32_t>(caps) & static_cast<uint32_t>(target)) != 0;
}
// 票据主体
struct CapabilityToken {
    std::string token_id;                    // 唯一 ID（UUID）
    std::string sandbox_id;                  // 所属沙盒实例 ID
    std::string issuer;                      // 签发者（controller 身份）
    std::chrono::system_clock::time_point issued_at;
    std::chrono::system_clock::time_point expires_at;
    // 能力位
    Capability capabilities = Capability::NONE;
    // 详细规则
    std::vector<std::string> allowed_exec_paths;   // 允许 exec 的程序路径
    std::vector<NetworkRule> network_rules;         // 出站网络规则
    std::vector<PathRule> path_rules;               // 文件访问规则
    // 资源限制
    uint64_t cpu_limit_ms = 5000;          // CPU 时间上限
    uint64_t memory_limit_bytes = 256 * 1024 * 1024;  // 内存上限
    uint32_t max_processes = 4;             // 最大进程数
    uint32_t max_open_files = 64;           // 最大 fd 数
    // HMAC 签名（SHA256-HMAC，用控制器密钥签名，沙盒进程不可篡改）
    std::string hmac_signature;             // hex 编码
    // ---- 方法 ----
    // 序列化用于签名（排除 hmac_signature 字段）
    std::string serialize_for_signing() const;
    // 检查是否过期
    bool is_expired() const;
    // 检查是否有某能力
    bool has(Capability cap) const;
    // 检查某路径是否允许 exec
    bool can_exec(const std::string& path) const;
    // 检查某网络目标是否允许
    bool can_network(const std::string& ip, uint16_t port, const std::string& proto) const;
    // 检查某文件路径是否允许访问
    bool can_file(const std::string& path, bool write) const;
    // JSON 序列化（用于 RPC 传递）
    std::string to_json() const;
    static std::optional<CapabilityToken> from_json(const std::string& json);
};
// 票据管理器：签发、验证、撤销
class CapabilityTokenManager {
public:
    explicit CapabilityTokenManager(std::string hmac_key);
    ~CapabilityTokenManager() = default;
    // 签发票据（自动签名）
    CapabilityToken issue(const std::string& sandbox_id,
                          Capability caps,
                          std::chrono::seconds ttl = std::chrono::hours(1));
    // 验证票据（签名 + 过期 + 撤销列表）
    bool verify(const CapabilityToken& token) const;
    // 撤销票据（运行时回收权限，不需要销毁沙盒）
    void revoke(const std::string& token_id);
    // 撤销某沙盒的所有票据
    void revoke_all_for_sandbox(const std::string& sandbox_id);
    // 检查票据是否被撤销
    bool is_revoked(const std::string& token_id) const;
    // 部分撤销：移除某能力（返回新票据，旧票据加入撤销列表）
    std::optional<CapabilityToken> recall_capability(const std::string& token_id, Capability to_remove);
    // 统计
    size_t active_count() const;
    size_t revoked_count() const;
private:
    std::string hmac_key_;
    mutable std::mutex mtx_;
    std::unordered_map<std::string, CapabilityToken> active_;   // token_id -> token
    std::unordered_set<std::string> revoked_;                      // 已撤销 token_id
    std::string sign(const std::string& data) const;
    static std::string generate_uuid();
};
} // namespace sandbox
} // namespace photon_kernel
#endif
