#ifndef PHOTON_KERNEL_SANDBOX_RESOURCE_PROXY_HPP
#define PHOTON_KERNEL_SANDBOX_RESOURCE_PROXY_HPP
// ResourceProxy —— 借鉴小米澎湃OS"空白通行证"（虚拟替身资源）思想。
// 沙盒内部代码请求访问密钥、数据库凭据、主机文件、网络，永远拿不到真实句柄；
// 控制器代理层根据 CapabilityToken 决定返回：
//   1. 真实资源（票据允许）
//   2. 虚拟替身数据（空白通行证，保护真实隐私）
//   3. 直接拒绝
//
// 对应 OpenSandbox Credential Vault：密钥永远不落入沙盒进程内存，全部代理中转。
#include <string>
#include <unordered_map>
#include <mutex>
#include <optional>
#include <memory>
#include "capability_token.hpp"
namespace photon_kernel {
namespace sandbox {
// 代理决策结果
enum class ProxyDecision {
    ALLOW_REAL,       // 返回真实资源
    ALLOW_DUMMY,      // 返回虚拟替身数据（空白通行证）
    DENY,             // 拒绝
};
struct ProxyResult {
    ProxyDecision decision;
    std::string data;           // 真实数据或虚拟替身数据
    std::string reason;         // 决策原因（用于审计）
};
// 密钥保险箱（Credential Vault）
class CredentialVault {
public:
    // 存储密钥（仅控制器可访问，沙盒永远拿不到明文）
    void store(const std::string& key, const std::string& value);
    // 代理获取：校验票据，决定返回真实密钥还是虚拟替身
    ProxyResult get(const std::string& key, const CapabilityToken& token) const;
    // 检查密钥是否存在
    bool exists(const std::string& key) const;
    // 删除密钥
    void remove(const std::string& key);
    size_t size() const;
private:
    mutable std::mutex mtx_;
    std::unordered_map<std::string, std::string> secrets_;
    // 虚拟替身数据（空白通行证）：当票据不允许时返回这些假数据
    static std::string dummy_value(const std::string& key);
};
// 文件访问代理
class FileProxy {
public:
    // 代理读文件：校验票据路径权限，决定返回真实内容/虚拟内容/拒绝
    ProxyResult read(const std::string& path, const CapabilityToken& token) const;
    // 代理写文件：校验票据写权限
    ProxyResult write(const std::string& path, const std::string& content,
                       const CapabilityToken& token) const;
};
// 网络访问代理
class NetworkProxy {
public:
    // 代理出站连接：校验票据网络规则，决定允许/拒绝
    ProxyResult connect(const std::string& host, uint16_t port,
                        const std::string& protocol,
                        const CapabilityToken& token) const;
    // DNS 解析代理（防止 DNS 隧道）
    ProxyResult resolve(const std::string& domain, const CapabilityToken& token) const;
};
// 统一资源代理（组合以上三个代理）
class ResourceProxy {
public:
    explicit ResourceProxy(std::shared_ptr<CredentialVault> vault = nullptr);
    // 代理密钥访问
    ProxyResult access_secret(const std::string& key, const CapabilityToken& token) const;
    // 代理文件访问
    ProxyResult access_file(const std::string& path, bool write,
                             const std::string& content,
                             const CapabilityToken& token) const;
    // 代理网络访问
    ProxyResult access_network(const std::string& host, uint16_t port,
                                const std::string& protocol,
                                const CapabilityToken& token) const;
    // 获取密钥保险箱引用
    CredentialVault& vault() { return *vault_; }
private:
    std::shared_ptr<CredentialVault> vault_;
    FileProxy file_proxy_;
    NetworkProxy network_proxy_;
};
} // namespace sandbox
} // namespace photon_kernel
#endif
