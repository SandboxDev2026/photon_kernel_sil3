// ResourceProxy 实现：密钥保险箱 + 文件代理 + 网络代理。
#include "photon_kernel/sandbox/resource_proxy.hpp"
#include <fstream>
#include <sstream>
namespace photon_kernel {
namespace sandbox {
// ==================== CredentialVault ====================
void CredentialVault::store(const std::string& key, const std::string& value) {
    std::lock_guard<std::mutex> lock(mtx_);
    secrets_[key] = value;
}
ProxyResult CredentialVault::get(const std::string& key, const CapabilityToken& token) const {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = secrets_.find(key);
    if (it == secrets_.end()) {
        return {ProxyDecision::DENY, "", "secret not found: " + key};
    }
    // 有 EXEC 或 NETWORK 能力则允许真实访问，否则返回虚拟替身（空白通行证）
    if (token.has(Capability::EXEC) || token.has(Capability::NETWORK)) {
        return {ProxyDecision::ALLOW_REAL, it->second, "secret access granted"};
    }
    return {ProxyDecision::ALLOW_DUMMY, dummy_value(key),
            "secret denied, returning dummy (blank pass)"};
}
bool CredentialVault::exists(const std::string& key) const {
    std::lock_guard<std::mutex> lock(mtx_);
    return secrets_.count(key) > 0;
}
void CredentialVault::remove(const std::string& key) {
    std::lock_guard<std::mutex> lock(mtx_);
    secrets_.erase(key);
}
size_t CredentialVault::size() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return secrets_.size();
}
std::string CredentialVault::dummy_value(const std::string& key) {
    if (key.find("api_key") != std::string::npos || key.find("API_KEY") != std::string::npos)
        return "sk-dummy-" + std::string(32, 'x');
    if (key.find("password") != std::string::npos || key.find("secret") != std::string::npos)
        return "dummy_password_12345";
    if (key.find("token") != std::string::npos)
        return "dummy_token_" + std::string(24, '0');
    return "dummy_value_for_" + key;
}
// ==================== FileProxy ====================
ProxyResult FileProxy::read(const std::string& path, const CapabilityToken& token) const {
    if (!token.can_file(path, false))
        return {ProxyDecision::DENY, "", "file read denied: " + path};
    std::ifstream f(path);
    if (!f.is_open()) return {ProxyDecision::DENY, "", "cannot open: " + path};
    std::ostringstream ss; ss << f.rdbuf();
    return {ProxyDecision::ALLOW_REAL, ss.str(), "file read granted"};
}
ProxyResult FileProxy::write(const std::string& path, const std::string& content,
                               const CapabilityToken& token) const {
    if (!token.can_file(path, true))
        return {ProxyDecision::DENY, "", "file write denied: " + path};
    std::ofstream f(path);
    if (!f.is_open()) return {ProxyDecision::DENY, "", "cannot open for write: " + path};
    f << content;
    return {ProxyDecision::ALLOW_REAL, "", "file write granted"};
}
// ==================== NetworkProxy ====================
ProxyResult NetworkProxy::connect(const std::string& host, uint16_t port,
                                    const std::string& protocol,
                                    const CapabilityToken& token) const {
    if (!token.can_network(host, port, protocol))
        return {ProxyDecision::DENY, "", "network denied: " + host + ":" + std::to_string(port)};
    return {ProxyDecision::ALLOW_REAL, "", "network granted"};
}
ProxyResult NetworkProxy::resolve(const std::string& domain, const CapabilityToken& token) const {
    if (!token.has(Capability::NETWORK))
        return {ProxyDecision::DENY, "", "DNS denied: no network capability"};
    return {ProxyDecision::ALLOW_REAL, "", "DNS granted (rate-limited)"};
}
// ==================== ResourceProxy ====================
ResourceProxy::ResourceProxy(std::shared_ptr<CredentialVault> vault)
    : vault_(vault ? vault : std::make_shared<CredentialVault>()) {}
ProxyResult ResourceProxy::access_secret(const std::string& key, const CapabilityToken& token) const {
    return vault_->get(key, token);
}
ProxyResult ResourceProxy::access_file(const std::string& path, bool write,
                                         const std::string& content, const CapabilityToken& token) const {
    return write ? file_proxy_.write(path, content, token) : file_proxy_.read(path, token);
}
ProxyResult ResourceProxy::access_network(const std::string& host, uint16_t port,
                                            const std::string& protocol, const CapabilityToken& token) const {
    return network_proxy_.connect(host, port, protocol, token);
}
} // namespace sandbox
} // namespace photon_kernel
