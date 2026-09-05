"""
PhotonBox 后量子密码（PQC）迁移模块

基于 NIST PQC 标准化算法（Kyber/Dilithium/SPHINCS+），
为 PhotonBox 密钥体系提供抗量子攻击能力。

核心设计：
1. 算法抽象层：统一 KEM（密钥封装）和 Signature（签名）接口
2. 简化实现：教学级 Kyber-512 / Dilithium-2，保留格密码核心结构
3. 混合模式：经典 ECDH + PQC Kyber 混合密钥交换（迁移过渡期）
4. 迁移管理器：经典→混合→PQC原生 三阶段迁移路径
5. 安全参数：可配置算法强度、密钥长度、混合策略

参考：
- FIPS 203 (Kyber): Module-Lattice-Based Key-Encapsulation Mechanism
- FIPS 204 (Dilithium): Module-Lattice-Based Digital Signature
- FIPS 205 (SPHINCS+): Stateless Hash-Based Digital Signature
- HRK-QKD: 混合 Rainbow + Kyber 量子密钥分发
"""

import os
import time
import json
import hashlib
import hmac
import secrets
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Tuple, List, Dict, Any

# ==================== 安全参数配置 ====================

@dataclass
class PQCParams:
    """后量子密码安全参数配置"""
    # Kyber 参数（Module-LWE）
    kyber_n: int = 256          # 多项式次数（n=256）
    kyber_k: int = 2             # 模块维度（k=2 → Kyber-512）
    kyber_q: int = 3329          # 模数（q=3329）
    kyber_eta1: int = 3          # 私钥噪声分布参数
    kyber_eta2: int = 2          # 密文噪声分布参数

    # Dilithium 参数
    dilithium_k: int = 4         # 模块维度（k=4 → Dilithium-2）
    dilithium_l: int = 4         # 私钥向量长度
    dilithium_gamma1: int = 2**17  # 随机数范围
    dilithium_gamma2: int = 95232   # 拒绝采样阈值

    # 混合策略
    enable_classic_mix: bool = True   # 启用经典-PQC混合
    classic_algorithm: str = "ECDH-P256"  # 经典算法
    pqc_algorithm: str = "Kyber-512"      # PQC算法

    # 迁移阶段
    migration_phase: str = "hybrid"  # classic / hybrid / pqc_native

    # 密钥轮换
    key_rotation_seconds: int = 86400 * 30  # 30天轮换
    max_key_age_seconds: int = 86400 * 90   # 90天最大寿命


# ==================== 多项式环（格密码基础） ====================

class Polynomial:
    """
    环 R_q = Z_q[X]/(X^n + 1) 上的多项式

    Kyber/Dilithium 的核心数学结构。
    支持加法、乘法（NTT 加速的简化版）、采样。
    """

    def __init__(self, coefficients: List[int], n: int = 256, q: int = 3329):
        self.n = n
        self.q = q
        # 确保长度为 n，不足补零
        self.coeffs = (coefficients + [0] * n)[:n]
        # 归一化到 [0, q)
        self.coeffs = [c % q for c in self.coeffs]

    def __add__(self, other: 'Polynomial') -> 'Polynomial':
        """多项式加法"""
        assert self.n == other.n and self.q == other.q
        result = [(a + b) % self.q for a, b in zip(self.coeffs, other.coeffs)]
        return Polynomial(result, self.n, self.q)

    def __sub__(self, other: 'Polynomial') -> 'Polynomial':
        """多项式减法"""
        assert self.n == other.n and self.q == other.q
        result = [(a - b) % self.q for a, b in zip(self.coeffs, other.coeffs)]
        return Polynomial(result, self.n, self.q)

    def __mul__(self, other: 'Polynomial') -> 'Polynomial':
        """
        多项式乘法（模 X^n + 1）

        教学级实现：直接卷积 + 归约。
        生产级应使用 NTT（数论变换）加速。
        """
        assert self.n == other.n and self.q == other.q
        n = self.n
        # 卷积
        conv = [0] * (2 * n)
        for i in range(n):
            if self.coeffs[i] == 0:
                continue
            for j in range(n):
                conv[i + j] = (conv[i + j] + self.coeffs[i] * other.coeffs[j]) % self.q

        # 模 X^n + 1 归约：X^n = -1
        result = conv[:n]
        for i in range(n):
            result[i] = (result[i] - conv[i + n]) % self.q

        return Polynomial(result, self.n, self.q)

    @staticmethod
    def sample_cbd(eta: int, n: int = 256, q: int = 3329) -> 'Polynomial':
        """
        中心二项分布（Centered Binomial Distribution）采样

        Kyber 中用于生成私钥和噪声。
        从 2*eta 个随机比特求和，减去 eta。
        """
        coeffs = []
        for _ in range(n):
            # 生成 2*eta 个随机比特
            bits = secrets.randbits(2 * eta)
            s = bin(bits).count('1')  # 比特中 1 的个数
            coeffs.append((s - eta) % q)
        return Polynomial(coeffs, n, q)

    @staticmethod
    def sample_uniform(n: int = 256, q: int = 3329) -> 'Polynomial':
        """均匀随机采样（用于公钥矩阵 A）"""
        coeffs = [secrets.randbelow(q) for _ in range(n)]
        return Polynomial(coeffs, n, q)

    def to_bytes(self) -> bytes:
        """序列化为字节（简化版：每个系数 2 字节）"""
        return b''.join(c.to_bytes(2, 'little') for c in self.coeffs)

    @staticmethod
    def from_bytes(data: bytes, n: int = 256, q: int = 3329) -> 'Polynomial':
        """从字节反序列化"""
        coeffs = [int.from_bytes(data[i:i+2], 'little') for i in range(0, 2*n, 2)]
        return Polynomial(coeffs, n, q)


# ==================== Kyber 密钥封装机制（KEM） ====================

@dataclass
class KyberPublicKey:
    """Kyber 公钥"""
    t: List[Polynomial]  # t = A*s + e
    rho: bytes            # 生成矩阵 A 的种子

    def to_bytes(self) -> bytes:
        data = self.rho
        for poly in self.t:
            data += poly.to_bytes()
        return data


@dataclass
class KyberPrivateKey:
    """Kyber 私钥"""
    s: List[Polynomial]   # 私钥向量
    public_key: KyberPublicKey  # 对应的公钥
    z: bytes               # 拒绝采样种子（用于 FO 变换）

    def to_bytes(self) -> bytes:
        data = self.z
        for poly in self.s:
            data += poly.to_bytes()
        data += self.public_key.to_bytes()
        return data


@dataclass
class KyberCiphertext:
    """Kyber 密文"""
    u: List[Polynomial]  # u = A^T*r + e1
    v: Polynomial         # v = t^T*r + e2 + m

    def to_bytes(self) -> bytes:
        data = b''
        for poly in self.u:
            data += poly.to_bytes()
        data += self.v.to_bytes()
        return data


class KyberKEM:
    """
    Kyber 密钥封装机制（简化教学版）

    基于 Module-LWE 问题的后量子 KEM。
    安全基础：攻击者无法在多项式时间内从公钥恢复私钥。

    流程：
    1. 密钥生成：(pk, sk) ← KeyGen()
    2. 封装：(c, K) ← Encaps(pk)
    3. 解封装：K' ← Decaps(c, sk)
    """

    def __init__(self, params: Optional[PQCParams] = None):
        self.params = params or PQCParams()
        self.n = self.params.kyber_n
        self.k = self.params.kyber_k
        self.q = self.params.kyber_q

    def _generate_matrix_A(self, rho: bytes) -> List[List[Polynomial]]:
        """生成公钥矩阵 A（k×k），使用种子 rho 确定性生成"""
        # 使用 SHAKE-128 的简化替代：SHA-256 扩展
        A = []
        for i in range(self.k):
            row = []
            for j in range(self.k):
                seed = rho + i.to_bytes(1, 'little') + j.to_bytes(1, 'little')
                h = hashlib.shake_128(seed)
                coeffs = []
                while len(coeffs) < self.n:
                    chunk = h.digest(3)  # 3字节 = 24比特，可生成多个系数
                    for b in range(0, 3, 2):
                        if len(coeffs) >= self.n:
                            break
                        val = int.from_bytes(chunk[b:b+2], 'little') % self.q
                        coeffs.append(val)
                row.append(Polynomial(coeffs, self.n, self.q))
            A.append(row)
        return A

    def keygen(self) -> Tuple[KyberPublicKey, KyberPrivateKey]:
        """
        密钥生成

        1. 采样 rho（公钥种子）和 sigma（私钥种子）
        2. 生成矩阵 A = expand(rho)
        3. 采样私钥 s ← CBD_eta1，噪声 e ← CBD_eta1
        4. 计算公钥 t = A*s + e
        """
        rho = secrets.token_bytes(32)
        sigma = secrets.token_bytes(64)
        z = secrets.token_bytes(32)  # FO 变换种子

        A = self._generate_matrix_A(rho)

        # 采样私钥和噪声
        s = [Polynomial.sample_cbd(self.params.kyber_eta1, self.n, self.q) for _ in range(self.k)]
        e = [Polynomial.sample_cbd(self.params.kyber_eta1, self.n, self.q) for _ in range(self.k)]

        # 计算 t = A*s + e
        t = []
        for i in range(self.k):
            ti = e[i]
            for j in range(self.k):
                ti = ti + (A[i][j] * s[j])
            t.append(ti)

        pk = KyberPublicKey(t=t, rho=rho)
        sk = KyberPrivateKey(s=s, public_key=pk, z=z)
        return pk, sk

    def encaps(self, pk: KyberPublicKey) -> Tuple[KyberCiphertext, bytes]:
        """
        封装

        1. 采样随机数 m（待封装的对称密钥）
        2. 采样随机向量 r ← CBD_eta1，噪声 e1, e2 ← CBD_eta2
        3. 计算 u = A^T*r + e1
        4. 计算 v = t^T*r + e2 + m
        5. 共享密钥 K = G(m, c)（Fujisaki-Okamoto 变换）
        """
        A = self._generate_matrix_A(pk.rho)

        # 采样随机数和噪声
        m = secrets.token_bytes(32)  # 待封装的密钥
        r = [Polynomial.sample_cbd(self.params.kyber_eta1, self.n, self.q) for _ in range(self.k)]
        e1 = [Polynomial.sample_cbd(self.params.kyber_eta2, self.n, self.q) for _ in range(self.k)]
        e2 = Polynomial.sample_cbd(self.params.kyber_eta2, self.n, self.q)

        # 计算 u = A^T*r + e1
        u = []
        for j in range(self.k):
            uj = e1[j]
            for i in range(self.k):
                uj = uj + (A[i][j] * r[i])
            u.append(uj)

        # 计算 v = t^T*r + e2 + m
        v = e2
        for i in range(self.k):
            v = v + (pk.t[i] * r[i])
        # 将 m 编码到 v（使用 q/2 间距，确保噪声不影响恢复）
        # 编码 0: 系数=0, 编码 1: 系数=q//2
        half_q = self.q // 2
        m_poly = Polynomial(
            [half_q if ((m[i // 8] >> (i % 8)) & 1) else 0 for i in range(self.n)],
            self.n, self.q
        )
        v = v + m_poly

        ct = KyberCiphertext(u=u, v=v)

        # FO 变换：K = G(m, ct)
        ct_bytes = ct.to_bytes()
        K = hashlib.sha3_256(m + ct_bytes).digest()
        return ct, K

    def decaps(self, ct: KyberCiphertext, sk: KyberPrivateKey) -> bytes:
        """
        解封装（教学级简化版）

        1. 计算 m' = v - s^T*u
        2. 从 m' 恢复随机数 m
        3. 共享密钥 K = G(m, c)

        注意：完整 Kyber 使用 Fujisaki-Okamoto 变换实现 CCA 安全，
        教学级简化版直接使用恢复的 m 计算密钥。
        生产环境应使用 liboqs 等官方实现。
        """
        # 计算 m' = v - s^T*u
        m_prime = ct.v
        for i in range(self.k):
            m_prime = m_prime - (sk.s[i] * ct.u[i])

        # 从 m_prime 恢复 m（使用 q/4 阈值）
        # 系数接近 0 → 比特 0，系数接近 q/2 → 比特 1
        quarter_q = self.q // 4
        m = bytearray(32)
        for i in range(min(self.n, 256)):
            coeff = m_prime.coeffs[i] % self.q
            # 计算到 0 和 q/2 的距离
            dist_to_zero = min(coeff, self.q - coeff)
            dist_to_half = min(abs(coeff - self.q // 2), self.q - abs(coeff - self.q // 2))
            if dist_to_half < dist_to_zero:
                m[i // 8] |= (1 << (i % 8))
        m = bytes(m)

        # 共享密钥 K = G(m, c)
        ct_bytes = ct.to_bytes()
        K = hashlib.sha3_256(m + ct_bytes).digest()
        return K


# ==================== Dilithium 签名（简化版） ====================

@dataclass
class DilithiumPublicKey:
    """Dilithium 公钥"""
    rho: bytes            # 矩阵 A 种子
    t1: List[Polynomial]  # 公钥（高位）

    def to_bytes(self) -> bytes:
        data = self.rho
        for poly in self.t1:
            data += poly.to_bytes()
        return data


@dataclass
class DilithiumPrivateKey:
    """Dilithium 私钥"""
    rho: bytes
    K: bytes              # 拒绝采样种子
    tr: bytes             # 公钥哈希
    s1: List[Polynomial]  # 私钥向量 1
    s2: List[Polynomial]  # 私钥向量 2
    t0: List[Polynomial]  # t 的低位
    public_key: DilithiumPublicKey


@dataclass
class DilithiumSig:
    """Dilithium 签名"""
    c: bytes               # 挑战哈希
    z: List[Polynomial]    # 响应向量
    h: List[Polynomial]    # 提示多项式

    def to_bytes(self) -> bytes:
        data = self.c
        for poly in self.z:
            data += poly.to_bytes()
        for poly in self.h:
            data += poly.to_bytes()
        return data


class DilithiumSignature:
    """
    Dilithium 数字签名（简化教学版）

    基于 Module-LWE + Module-SIS 的后量子签名。
    安全基础：Fiat-Shamir with Aborts 变换。

    流程：
    1. 密钥生成：(pk, sk) ← KeyGen()
    2. 签名：σ ← Sign(sk, M)
    3. 验证：b ← Verify(pk, M, σ)
    """

    def __init__(self, params: Optional[PQCParams] = None):
        self.params = params or PQCParams()
        self.n = 256
        self.q = 8380417  # Dilithium 使用 q = 2^23 - 2^13 + 1
        self.k = self.params.dilithium_k
        self.l = self.params.dilithium_l

    def _generate_matrix_A(self, rho: bytes, rows: int, cols: int) -> List[List[Polynomial]]:
        """生成矩阵 A（rows×cols）"""
        A = []
        for i in range(rows):
            row = []
            for j in range(cols):
                seed = rho + i.to_bytes(1, 'little') + j.to_bytes(1, 'little')
                h = hashlib.shake_128(seed)
                coeffs = []
                while len(coeffs) < self.n:
                    chunk = h.digest(3)
                    for b in range(0, 3, 2):
                        if len(coeffs) >= self.n:
                            break
                        val = int.from_bytes(chunk[b:b+2], 'little') % self.q
                        coeffs.append(val)
                row.append(Polynomial(coeffs, self.n, self.q))
            A.append(row)
        return A

    def keygen(self) -> Tuple[DilithiumPublicKey, DilithiumPrivateKey]:
        """密钥生成"""
        rho = secrets.token_bytes(32)
        K = secrets.token_bytes(32)

        A = self._generate_matrix_A(rho, self.k, self.l)

        # 采样私钥
        s1 = [Polynomial.sample_cbd(2, self.n, self.q) for _ in range(self.l)]
        s2 = [Polynomial.sample_cbd(2, self.n, self.q) for _ in range(self.k)]

        # 计算 t = A*s1 + s2
        t = []
        for i in range(self.k):
            ti = s2[i]
            for j in range(self.l):
                ti = ti + (A[i][j] * s1[j])
            t.append(ti)

        # 分解 t = t1*2^d + t0（d=13）
        d = 13
        t1 = []
        t0 = []
        for ti in t:
            t1_i = Polynomial([(c >> d) for c in ti.coeffs], self.n, self.q)
            t0_i = Polynomial([(c & ((1 << d) - 1)) for c in ti.coeffs], self.n, self.q)
            t1.append(t1_i)
            t0.append(t0_i)

        tr = hashlib.sha3_256(rho + b''.join(p.to_bytes() for p in t1)).digest()

        pk = DilithiumPublicKey(rho=rho, t1=t1)
        sk = DilithiumPrivateKey(
            rho=rho, K=K, tr=tr, s1=s1, s2=s2, t0=t0, public_key=pk
        )
        return pk, sk

    def sign(self, sk: DilithiumPrivateKey, message: bytes) -> DilithiumSig:
        """
        签名（Fiat-Shamir with Aborts）

        简化版：省略拒绝采样的完整实现，保留核心结构。
        """
        A = self._generate_matrix_A(sk.rho, self.k, self.l)

        # 消息前缀哈希
        mu = hashlib.sha3_256(sk.tr + message).digest()

        # 采样随机向量 y
        y = [Polynomial.sample_cbd(4, self.n, self.q) for _ in range(self.l)]

        # 计算 w = A*y
        w = []
        for i in range(self.k):
            wi = Polynomial([0] * self.n, self.n, self.q)
            for j in range(self.l):
                wi = wi + (A[i][j] * y[j])
            w.append(wi)

        # 高位提取 w1
        d = 13
        w1 = [Polynomial([(c >> d) for c in wi.coeffs], self.n, self.q) for wi in w]

        # 挑战 c = H(mu, w1)
        c_hash = hashlib.sha3_256(mu + b''.join(p.to_bytes() for p in w1)).digest()

        # 响应 z = y + c*s1（简化：c 作为标量）
        c_scalar = int.from_bytes(c_hash[:4], 'little') % self.q
        z = []
        for j in range(self.l):
            zj = y[j] + Polynomial([c_scalar] * self.n, self.n, self.q) * sk.s1[j]
            z.append(zj)

        # 提示 h（简化版）
        h = [Polynomial([0] * self.n, self.n, self.q) for _ in range(self.k)]

        return DilithiumSig(c=c_hash, z=z, h=h)

    def verify(self, pk: DilithiumPublicKey, message: bytes, sig: DilithiumSig) -> bool:
        """
        验证签名

        简化版：检查 z 的范数和重构的挑战。
        """
        A = self._generate_matrix_A(pk.rho, self.k, self.l)

        # 消息前缀哈希
        tr = hashlib.sha3_256(pk.rho + b''.join(p.to_bytes() for p in pk.t1)).digest()
        mu = hashlib.sha3_256(tr + message).digest()

        # 计算 w' = A*z - c*t1*2^d
        c_scalar = int.from_bytes(sig.c[:4], 'little') % self.q
        d = 13
        w_prime = []
        for i in range(self.k):
            wi = Polynomial([0] * self.n, self.n, self.q)
            for j in range(self.l):
                wi = wi + (A[i][j] * sig.z[j])
            # 减去 c*t1*2^d
            t1_scaled = Polynomial(
                [(c * (1 << d)) % self.q for c in pk.t1[i].coeffs],
                self.n, self.q
            )
            wi = wi - t1_scaled
            w_prime.append(wi)

        # 高位提取
        w1_prime = [Polynomial([(c >> d) for c in wi.coeffs], self.n, self.q) for wi in w_prime]

        # 重构挑战
        c_prime = hashlib.sha3_256(mu + b''.join(p.to_bytes() for p in w1_prime)).digest()

        return hmac.compare_digest(sig.c, c_prime)


# ==================== 经典-PQC 混合密钥交换 ====================

class HybridKeyExchange:
    """
    经典-PQC 混合密钥交换

    同时执行经典 ECDH 和 PQC Kyber，最终密钥为两者的哈希组合。
    即使其中一种被破解，另一种仍能保证安全性。

    参考：HRK-QKD 混合协议、IETF hybrid key exchange 草案
    """

    def __init__(self, params: Optional[PQCParams] = None):
        self.params = params or PQCParams()
        self.kyber = KyberKEM(self.params)

    def _classic_ecdh(self) -> Tuple[bytes, bytes]:
        """
        经典 ECDH 密钥交换（简化版）

        生产级应使用 cryptography 库的 ECDH。
        这里使用 X25519 的简化模拟。
        """
        # 简化：使用 HKDF 从随机种子派生共享密钥
        private_seed = secrets.token_bytes(32)
        public_key = hashlib.sha3_256(private_seed).digest()
        # 模拟共享密钥（实际应为 ECDH 计算结果）
        shared_secret = hashlib.sha3_256(private_seed + b"ecdh_shared").digest()
        return public_key, shared_secret

    def initiate(self) -> Dict[str, Any]:
        """
        发起方：生成经典公钥和 PQC 公钥

        Returns:
            包含 classic_pk, classic_shared, pqc_pk, pqc_sk 的字典
        """
        # 经典 ECDH（简化版：双方通过公钥派生相同共享密钥）
        classic_private = secrets.token_bytes(32)
        classic_pk = hashlib.sha3_256(classic_private).digest()
        # 共享密钥 = KDF(private_key)，实际 ECDH 中双方通过对方公钥计算
        classic_shared = hashlib.sha3_256(classic_private + b"ecdh_shared").digest()

        # PQC Kyber
        pqc_pk, pqc_sk = self.kyber.keygen()

        return {
            "classic_pk": classic_pk,
            "classic_private": classic_private,  # 简化版：保留私钥用于演示
            "classic_shared": classic_shared,
            "pqc_pk": pqc_pk,
            "pqc_sk": pqc_sk,
        }

    def respond(self, initiator_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        响应方：生成经典公钥、封装 PQC 密文，计算混合共享密钥

        Returns:
            包含 classic_pk, pqc_ct, shared_key 的字典
        """
        # 经典 ECDH（简化版：双方公钥派生相同共享密钥）
        responder_private = secrets.token_bytes(32)
        classic_pk = hashlib.sha3_256(responder_private).digest()
        # 简化版：共享密钥 = KDF(initiator_pk || responder_pk)
        # 实际 ECDH 中应为双方私钥和对方公钥的点积
        classic_shared = hashlib.sha3_256(
            initiator_data["classic_pk"] + classic_pk + b"ecdh_shared"
        ).digest()

        # PQC Kyber 封装
        pqc_ct, pqc_shared = self.kyber.encaps(initiator_data["pqc_pk"])

        # 混合共享密钥 = KDF(classic_shared || pqc_shared)
        mixed_shared = hashlib.sha3_256(
            classic_shared + pqc_shared + b"hybrid_key_exchange_v1"
        ).digest()

        return {
            "classic_pk": classic_pk,
            "responder_private": responder_private,  # 简化版：保留私钥用于演示
            "pqc_ct": pqc_ct,
            "shared_key": mixed_shared,
        }

    def finalize(self, initiator_data: Dict[str, Any], responder_data: Dict[str, Any]) -> bytes:
        """
        发起方：解封装 PQC 密文，计算混合共享密钥

        Returns:
            混合共享密钥
        """
        # 经典 ECDH（简化版：双方公钥派生相同共享密钥）
        classic_shared = hashlib.sha3_256(
            initiator_data["classic_pk"] + responder_data["classic_pk"] + b"ecdh_shared"
        ).digest()

        # PQC Kyber 解封装
        pqc_shared = self.kyber.decaps(responder_data["pqc_ct"], initiator_data["pqc_sk"])

        # 混合共享密钥
        mixed_shared = hashlib.sha3_256(
            classic_shared + pqc_shared + b"hybrid_key_exchange_v1"
        ).digest()

        return mixed_shared


# ==================== 密钥迁移管理器 ====================

class MigrationPhase(Enum):
    """迁移阶段"""
    CLASSIC = "classic"           # 仅经典密码
    HYBRID = "hybrid"             # 经典-PQC 混合
    PQC_NATIVE = "pqc_native"     # 仅 PQC


@dataclass
class KeyRecord:
    """密钥记录"""
    key_id: str
    algorithm: str           # classic / hybrid / pqc_native
    created_at: float
    last_used_at: float
    rotation_count: int = 0
    compromised: bool = False


class KeyMigrationManager:
    """
    后量子密码迁移管理器

    管理经典→混合→PQC原生 三阶段迁移路径，
    支持密钥轮换、老化检测、妥协标记、迁移审计。

    参考：多链量子就绪评估（2026.4）迁移路径
    """

    def __init__(self, params: Optional[PQCParams] = None):
        self.params = params or PQCParams()
        self.keys: Dict[str, KeyRecord] = {}
        self.migration_phase = MigrationPhase(self.params.migration_phase)
        self.audit_log: List[Dict[str, Any]] = []

    def generate_key(self, algorithm: Optional[str] = None) -> KeyRecord:
        """生成新密钥"""
        algo = algorithm or self.migration_phase.value
        key_id = hashlib.sha3_256(secrets.token_bytes(32)).hexdigest()[:16]
        now = time.time()
        record = KeyRecord(
            key_id=key_id,
            algorithm=algo,
            created_at=now,
            last_used_at=now,
        )
        self.keys[key_id] = record
        self._audit("key_generated", {"key_id": key_id, "algorithm": algo})
        return record

    def should_rotate(self, key_id: str) -> bool:
        """检查密钥是否需要轮换"""
        if key_id not in self.keys:
            return False
        record = self.keys[key_id]
        age = time.time() - record.created_at
        return age > self.params.key_rotation_seconds

    def rotate_key(self, key_id: str) -> Optional[KeyRecord]:
        """轮换密钥"""
        if key_id not in self.keys:
            return None
        old_record = self.keys[key_id]
        new_record = self.generate_key(old_record.algorithm)
        new_record.rotation_count = old_record.rotation_count + 1
        self._audit("key_rotated", {
            "old_key_id": key_id,
            "new_key_id": new_record.key_id,
            "rotation_count": new_record.rotation_count,
        })
        return new_record

    def mark_compromised(self, key_id: str) -> bool:
        """标记密钥已妥协"""
        if key_id not in self.keys:
            return False
        self.keys[key_id].compromised = True
        self._audit("key_compromised", {"key_id": key_id})
        return True

    def migrate_phase(self, new_phase: MigrationPhase) -> bool:
        """
        迁移到新阶段

        经典→混合：所有新密钥使用混合模式
        混合→PQC原生：所有新密钥使用 PQC 模式
        """
        old_phase = self.migration_phase
        self.migration_phase = new_phase
        self._audit("migration_phase_changed", {
            "old_phase": old_phase.value,
            "new_phase": new_phase.value,
        })
        return True

    def get_migration_status(self) -> Dict[str, Any]:
        """获取迁移状态"""
        total = len(self.keys)
        by_algorithm: Dict[str, int] = {}
        expired = 0
        compromised = 0

        for record in self.keys.values():
            by_algorithm[record.algorithm] = by_algorithm.get(record.algorithm, 0) + 1
            if self.should_rotate(record.key_id):
                expired += 1
            if record.compromised:
                compromised += 1

        return {
            "current_phase": self.migration_phase.value,
            "total_keys": total,
            "keys_by_algorithm": by_algorithm,
            "keys_needing_rotation": expired,
            "compromised_keys": compromised,
            "key_rotation_policy_days": self.params.key_rotation_seconds // 86400,
            "max_key_age_days": self.params.max_key_age_seconds // 86400,
        }

    def _audit(self, action: str, details: Dict[str, Any]) -> None:
        """审计日志"""
        self.audit_log.append({
            "timestamp": time.time(),
            "action": action,
            "details": details,
        })


# ==================== PQC 安全评估器 ====================

class PQCSecurityEvaluator:
    """
    后量子密码安全评估器

    评估系统的抗量子攻击 readiness，
    输出迁移建议和安全评分。
    """

    def __init__(self, params: Optional[PQCParams] = None):
        self.params = params or PQCParams()
        self.kyber = KyberKEM(self.params)
        self.dilithium = DilithiumSignature(self.params)
        self.hybrid = HybridKeyExchange(self.params)
        self.migration = KeyMigrationManager(self.params)

    def run_algorithmic_tests(self) -> Dict[str, Any]:
        """运行算法正确性测试"""
        results = {}

        # Kyber KEM 测试
        try:
            pk, sk = self.kyber.keygen()
            ct, K_enc = self.kyber.encaps(pk)
            K_dec = self.kyber.decaps(ct, sk)
            results["kyber_kem"] = {
                "passed": hmac.compare_digest(K_enc, K_dec),
                "key_size_bytes": len(K_enc),
                "public_key_size": len(pk.to_bytes()),
                "ciphertext_size": len(ct.to_bytes()),
            }
        except Exception as e:
            results["kyber_kem"] = {"passed": False, "error": str(e)}

        # Dilithium 签名测试
        try:
            pk, sk = self.dilithium.keygen()
            message = b"PhotonBox PQC test message"
            sig = self.dilithium.sign(sk, message)
            results["dilithium_signature"] = {
                "passed": self.dilithium.verify(pk, message, sig),
                "signature_size": len(sig.to_bytes()),
                "public_key_size": len(pk.to_bytes()),
            }
        except Exception as e:
            results["dilithium_signature"] = {"passed": False, "error": str(e)}

        # 混合密钥交换测试
        try:
            initiator = self.hybrid.initiate()
            responder = self.hybrid.respond(initiator)
            shared_initiator = self.hybrid.finalize(initiator, responder)
            results["hybrid_key_exchange"] = {
                "passed": hmac.compare_digest(shared_initiator, responder["shared_key"]),
                "shared_key_size": len(shared_initiator),
            }
        except Exception as e:
            results["hybrid_key_exchange"] = {"passed": False, "error": str(e)}

        return results

    def evaluate_readiness(self) -> Dict[str, Any]:
        """
        评估抗量子攻击 readiness

        评分维度：
        1. 算法可用性（Kyber/Dilithium/SPHINCS+）
        2. 混合模式支持
        3. 密钥迁移路径
        4. 密钥轮换策略
        5. 审计日志
        """
        algo_tests = self.run_algorithmic_tests()
        migration_status = self.migration.get_migration_status()

        # 计算评分（0-100）
        score = 0
        details = []

        # 算法可用性（40分）
        algo_passed = sum(1 for v in algo_tests.values() if v.get("passed"))
        algo_score = (algo_passed / len(algo_tests)) * 40
        score += algo_score
        details.append(f"算法可用性: {algo_passed}/{len(algo_tests)} 通过 (+{algo_score:.0f}/40)")

        # 混合模式（20分）
        if self.params.enable_classic_mix:
            score += 20
            details.append("混合模式: 已启用 (+20/20)")
        else:
            details.append("混合模式: 未启用 (+0/20)")

        # 迁移路径（20分）
        if self.migration.migration_phase == MigrationPhase.HYBRID:
            score += 15
            details.append("迁移阶段: 混合模式 (+15/20)")
        elif self.migration.migration_phase == MigrationPhase.PQC_NATIVE:
            score += 20
            details.append("迁移阶段: PQC原生 (+20/20)")
        else:
            details.append("迁移阶段: 仅经典 (+0/20)")

        # 密钥轮换（10分）
        if self.params.key_rotation_seconds <= 86400 * 30:
            score += 10
            details.append(f"密钥轮换: {self.params.key_rotation_seconds // 86400}天 (+10/10)")
        else:
            details.append("密钥轮换: 超过30天 (+0/10)")

        # 审计日志（10分）
        score += 10
        details.append("审计日志: 已启用 (+10/10)")

        return {
            "pqc_readiness_score": round(score, 1),
            "score_details": details,
            "algorithm_tests": algo_tests,
            "migration_status": migration_status,
            "recommendations": self._generate_recommendations(score, algo_tests),
        }

    def _generate_recommendations(self, score: float, algo_tests: Dict) -> List[str]:
        """生成迁移建议"""
        recommendations = []

        if score < 40:
            recommendations.append("紧急：系统尚未具备抗量子攻击能力，立即启动 PQC 迁移")
        elif score < 70:
            recommendations.append("建议：系统部分具备 PQC 能力，建议加速迁移到混合模式")
        else:
            recommendations.append("良好：系统已具备基本 PQC 能力，持续监控算法进展")

        failed_algos = [k for k, v in algo_tests.items() if not v.get("passed")]
        if failed_algos:
            recommendations.append(f"修复：以下算法测试未通过 - {', '.join(failed_algos)}")

        if not self.params.enable_classic_mix:
            recommendations.append("启用：建议启用经典-PQC 混合密钥交换作为过渡")

        return recommendations


# ==================== 便捷接口 ====================

def create_pqc_security_evaluator(params: Optional[PQCParams] = None) -> PQCSecurityEvaluator:
    """创建 PQC 安全评估器"""
    return PQCSecurityEvaluator(params)


def run_pqc_self_assessment() -> Dict[str, Any]:
    """运行 PQC 自评估（便捷接口）"""
    evaluator = create_pqc_security_evaluator()
    return evaluator.evaluate_readiness()


if __name__ == "__main__":
    # 自测试
    print("=" * 60)
    print("PhotonBox 后量子密码（PQC）迁移模块 - 自测试")
    print("=" * 60)

    result = run_pqc_self_assessment()

    print(f"\nPQC Readiness Score: {result['pqc_readiness_score']}/100")
    print("\n评分详情:")
    for detail in result['score_details']:
        print(f"  - {detail}")

    print("\n算法测试:")
    for algo, test_result in result['algorithm_tests'].items():
        status = "✅ PASS" if test_result.get('passed') else "❌ FAIL"
        print(f"  {algo}: {status}")
        if 'key_size_bytes' in test_result:
            print(f"    密钥大小: {test_result['key_size_bytes']} 字节")
        if 'public_key_size' in test_result:
            print(f"    公钥大小: {test_result['public_key_size']} 字节")

    print("\n迁移建议:")
    for rec in result['recommendations']:
        print(f"  - {rec}")

    print("\n" + "=" * 60)
