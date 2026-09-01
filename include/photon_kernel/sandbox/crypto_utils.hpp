#ifndef PHOTON_KERNEL_SANDBOX_CRYPTO_UTILS_HPP
#define PHOTON_KERNEL_SANDBOX_CRYPTO_UTILS_HPP
// 纯 C++ 实现的 SHA256 + HMAC-SHA256（不依赖 OpenSSL）。
// 当系统无 OpenSSL 时作为 fallback，保证审计防篡改功能可用。
// 参考 FIPS 180-4 和 RFC 2104 标准实现。
#include <cstdint>
#include <cstddef>
#include <string>
#include <array>
namespace photon_kernel {
namespace sandbox {
namespace crypto {
// SHA256 摘要（32 字节）
using Sha256Digest = std::array<uint8_t, 32>;
// 计算 SHA256
Sha256Digest sha256(const uint8_t* data, size_t len);
Sha256Digest sha256(const std::string& data);
// 计算 HMAC-SHA256
Sha256Digest hmac_sha256(const uint8_t* key, size_t key_len,
                          const uint8_t* data, size_t data_len);
Sha256Digest hmac_sha256(const std::string& key, const std::string& data);
// 转为十六进制字符串
std::string to_hex(const uint8_t* data, size_t len);
std::string to_hex(const Sha256Digest& digest);
} // namespace crypto
} // namespace sandbox
} // namespace photon_kernel
#endif
