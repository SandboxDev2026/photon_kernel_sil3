// 纯 C++ 实现的 SHA256 + HMAC-SHA256（不依赖 OpenSSL）。
// 参考 FIPS 180-4 (SHA256) 和 RFC 2104 (HMAC)。
#include "photon_kernel/sandbox/crypto_utils.hpp"
#include <cstring>
namespace photon_kernel {
namespace sandbox {
namespace crypto {
namespace {
constexpr uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};
inline uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
inline uint32_t bigsig0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
inline uint32_t bigsig1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
inline uint32_t smallsig0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
inline uint32_t smallsig1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }
void sha256_transform(uint32_t state[8], const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = (static_cast<uint32_t>(block[i*4]) << 24) |
               (static_cast<uint32_t>(block[i*4+1]) << 16) |
               (static_cast<uint32_t>(block[i*4+2]) << 8) |
               (static_cast<uint32_t>(block[i*4+3]));
    }
    for (int i = 16; i < 64; ++i)
        w[i] = smallsig1(w[i-2]) + w[i-7] + smallsig0(w[i-15]) + w[i-16];
    uint32_t a=state[0], b=state[1], c=state[2], d=state[3];
    uint32_t e=state[4], f=state[5], g=state[6], h=state[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t t1 = h + bigsig1(e) + ch(e,f,g) + K[i] + w[i];
        uint32_t t2 = bigsig0(a) + maj(a,b,c);
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
    state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
}
} // anon
Sha256Digest sha256(const uint8_t* data, size_t len) {
    uint32_t state[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                          0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    uint8_t block[64];
    size_t i = 0;
    for (; i + 64 <= len; i += 64) {
        std::memcpy(block, data+i, 64);
        sha256_transform(state, block);
    }
    size_t rem = len - i;
    std::memset(block, 0, 64);
    std::memcpy(block, data+i, rem);
    block[rem] = 0x80;
    if (rem >= 56) { sha256_transform(state, block); std::memset(block, 0, 64); }
    uint64_t bit_len = static_cast<uint64_t>(len) * 8;
    for (int j = 0; j < 8; ++j)
        block[63-j] = static_cast<uint8_t>(bit_len >> (j*8));
    sha256_transform(state, block);
    Sha256Digest digest;
    for (int j = 0; j < 8; ++j) {
        digest[j*4]   = static_cast<uint8_t>(state[j] >> 24);
        digest[j*4+1] = static_cast<uint8_t>(state[j] >> 16);
        digest[j*4+2] = static_cast<uint8_t>(state[j] >> 8);
        digest[j*4+3] = static_cast<uint8_t>(state[j]);
    }
    return digest;
}
Sha256Digest sha256(const std::string& data) {
    return sha256(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}
Sha256Digest hmac_sha256(const uint8_t* key, size_t key_len,
                          const uint8_t* data, size_t data_len) {
    constexpr size_t B = 64;
    uint8_t k_prime[B];
    std::memset(k_prime, 0, B);
    if (key_len > B) {
        Sha256Digest kh = sha256(key, key_len);
        std::memcpy(k_prime, kh.data(), 32);
    } else {
        std::memcpy(k_prime, key, key_len);
    }
    uint8_t ipad[B], opad[B];
    for (size_t i = 0; i < B; ++i) {
        ipad[i] = k_prime[i] ^ 0x36;
        opad[i] = k_prime[i] ^ 0x5c;
    }
    size_t inner_len = B + data_len;
    uint8_t* inner_buf = new uint8_t[inner_len];
    std::memcpy(inner_buf, ipad, B);
    std::memcpy(inner_buf + B, data, data_len);
    Sha256Digest inner = sha256(inner_buf, inner_len);
    delete[] inner_buf;
    uint8_t outer_buf[B + 32];
    std::memcpy(outer_buf, opad, B);
    std::memcpy(outer_buf + B, inner.data(), 32);
    return sha256(outer_buf, B + 32);
}
Sha256Digest hmac_sha256(const std::string& key, const std::string& data) {
    return hmac_sha256(reinterpret_cast<const uint8_t*>(key.data()), key.size(),
                        reinterpret_cast<const uint8_t*>(data.data()), data.size());
}
std::string to_hex(const uint8_t* data, size_t len) {
    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(hex[data[i] >> 4]);
        out.push_back(hex[data[i] & 0x0f]);
    }
    return out;
}
std::string to_hex(const Sha256Digest& digest) {
    return to_hex(digest.data(), digest.size());
}
} // crypto
} // sandbox
} // photon_kernel
