"""
PhotonBox 后量子密码（PQC）迁移模块 - 单元测试

覆盖：
1. 多项式环运算（加法、减法、乘法、采样）
2. Kyber KEM（密钥生成、封装、解封装、密钥一致性）
3. 混合密钥交换（发起、响应、完成、密钥一致性）
4. 密钥迁移管理器（生成、轮换、妥协标记、阶段迁移）
5. PQC 安全评估器（算法测试、readiness 评分、建议生成）
"""

import unittest
import time
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evolution.post_quantum_crypto import (
    PQCParams, Polynomial, KyberKEM, KyberPublicKey, KyberPrivateKey,
    KyberCiphertext, HybridKeyExchange, KeyMigrationManager,
    MigrationPhase, KeyRecord, PQCSecurityEvaluator,
    create_pqc_security_evaluator, run_pqc_self_assessment,
)


class TestPolynomial(unittest.TestCase):
    """多项式环运算测试"""

    def setUp(self):
        self.n = 256
        self.q = 3329

    def test_polynomial_creation(self):
        """多项式创建和归一化"""
        p = Polynomial([1, 2, 3], n=self.n, q=self.q)
        self.assertEqual(len(p.coeffs), self.n)
        self.assertEqual(p.coeffs[0], 1)
        self.assertEqual(p.coeffs[1], 2)
        self.assertEqual(p.coeffs[2], 3)
        self.assertEqual(p.coeffs[3], 0)  # 自动补零

    def test_polynomial_modulo(self):
        """系数模 q 归一化"""
        p = Polynomial([self.q, self.q + 1, -1], n=self.n, q=self.q)
        self.assertEqual(p.coeffs[0], 0)
        self.assertEqual(p.coeffs[1], 1)
        self.assertEqual(p.coeffs[2], self.q - 1)

    def test_polynomial_addition(self):
        """多项式加法"""
        a = Polynomial([1, 2, 3], n=self.n, q=self.q)
        b = Polynomial([4, 5, 6], n=self.n, q=self.q)
        c = a + b
        self.assertEqual(c.coeffs[0], 5)
        self.assertEqual(c.coeffs[1], 7)
        self.assertEqual(c.coeffs[2], 9)

    def test_polynomial_subtraction(self):
        """多项式减法"""
        a = Polynomial([5, 7, 9], n=self.n, q=self.q)
        b = Polynomial([1, 2, 3], n=self.n, q=self.q)
        c = a - b
        self.assertEqual(c.coeffs[0], 4)
        self.assertEqual(c.coeffs[1], 5)
        self.assertEqual(c.coeffs[2], 6)

    def test_polynomial_multiplication_basic(self):
        """多项式乘法（模 X^n + 1）"""
        # (1 + x) * (1 + x) = 1 + 2x + x^2
        a = Polynomial([1, 1], n=4, q=self.q)
        b = Polynomial([1, 1], n=4, q=self.q)
        c = a * b
        self.assertEqual(c.coeffs[0], 1)
        self.assertEqual(c.coeffs[1], 2)
        self.assertEqual(c.coeffs[2], 1)
        self.assertEqual(c.coeffs[3], 0)

    def test_polynomial_multiplication_reduction(self):
        """多项式乘法模 X^n + 1 归约"""
        # x^3 * x = x^4 = -1 (mod x^4 + 1)
        a = Polynomial([0, 0, 0, 1], n=4, q=self.q)
        b = Polynomial([0, 1, 0, 0], n=4, q=self.q)
        c = a * b
        self.assertEqual(c.coeffs[0], self.q - 1)  # -1 mod q

    def test_sample_uniform(self):
        """均匀随机采样"""
        p = Polynomial.sample_uniform(n=self.n, q=self.q)
        self.assertEqual(len(p.coeffs), self.n)
        for c in p.coeffs:
            self.assertTrue(0 <= c < self.q)

    def test_sample_cbd(self):
        """中心二项分布采样"""
        p = Polynomial.sample_cbd(eta=3, n=self.n, q=self.q)
        self.assertEqual(len(p.coeffs), self.n)
        # CBD(eta=3) 的系数应在 [-3, 3] 范围内（模 q 后）
        for c in p.coeffs:
            self.assertTrue(0 <= c < self.q)

    def test_serialization(self):
        """多项式序列化和反序列化"""
        p = Polynomial.sample_uniform(n=self.n, q=self.q)
        data = p.to_bytes()
        self.assertEqual(len(data), 2 * self.n)  # 每个系数 2 字节
        p2 = Polynomial.from_bytes(data, n=self.n, q=self.q)
        self.assertEqual(p.coeffs, p2.coeffs)


class TestKyberKEM(unittest.TestCase):
    """Kyber 密钥封装机制测试"""

    def setUp(self):
        self.params = PQCParams()
        self.kyber = KyberKEM(self.params)

    def test_keygen(self):
        """密钥生成"""
        pk, sk = self.kyber.keygen()
        self.assertIsInstance(pk, KyberPublicKey)
        self.assertIsInstance(sk, KyberPrivateKey)
        self.assertEqual(len(pk.t), self.params.kyber_k)
        self.assertEqual(len(sk.s), self.params.kyber_k)
        self.assertEqual(len(pk.rho), 32)
        self.assertEqual(len(sk.z), 32)

    def test_encaps(self):
        """封装"""
        pk, sk = self.kyber.keygen()
        ct, K = self.kyber.encaps(pk)
        self.assertIsInstance(ct, KyberCiphertext)
        self.assertEqual(len(ct.u), self.params.kyber_k)
        self.assertEqual(len(K), 32)  # SHA-256 输出

    def test_decaps_consistency(self):
        """解封装密钥一致性（核心测试）"""
        for _ in range(5):  # 多次测试确保稳定性
            pk, sk = self.kyber.keygen()
            ct, K_enc = self.kyber.encaps(pk)
            K_dec = self.kyber.decaps(ct, sk)
            self.assertEqual(K_enc, K_dec, "Kyber KEM 封装/解封装密钥不一致")

    def test_different_keys_different_ciphertexts(self):
        """不同密钥生成不同密文"""
        pk1, _ = self.kyber.keygen()
        pk2, _ = self.kyber.keygen()
        ct1, K1 = self.kyber.encaps(pk1)
        ct2, K2 = self.kyber.encaps(pk2)
        self.assertNotEqual(K1, K2)

    def test_public_key_serialization(self):
        """公钥序列化"""
        pk, _ = self.kyber.keygen()
        data = pk.to_bytes()
        self.assertTrue(len(data) > 0)
        self.assertEqual(len(data), 32 + self.params.kyber_k * 2 * 256)  # rho + k个多项式

    def test_ciphertext_serialization(self):
        """密文序列化"""
        pk, _ = self.kyber.keygen()
        ct, _ = self.kyber.encaps(pk)
        data = ct.to_bytes()
        self.assertTrue(len(data) > 0)


class TestHybridKeyExchange(unittest.TestCase):
    """经典-PQC 混合密钥交换测试"""

    def setUp(self):
        self.params = PQCParams()
        self.hybrid = HybridKeyExchange(self.params)

    def test_initiate(self):
        """发起方初始化"""
        data = self.hybrid.initiate()
        self.assertIn("classic_pk", data)
        self.assertIn("pqc_pk", data)
        self.assertIn("pqc_sk", data)
        self.assertEqual(len(data["classic_pk"]), 32)

    def test_respond(self):
        """响应方响应"""
        initiator = self.hybrid.initiate()
        responder = self.hybrid.respond(initiator)
        self.assertIn("classic_pk", responder)
        self.assertIn("pqc_ct", responder)
        self.assertIn("shared_key", responder)
        self.assertEqual(len(responder["shared_key"]), 32)

    def test_full_exchange_consistency(self):
        """完整密钥交换一致性（核心测试）"""
        for _ in range(5):
            initiator = self.hybrid.initiate()
            responder = self.hybrid.respond(initiator)
            shared_initiator = self.hybrid.finalize(initiator, responder)
            self.assertEqual(
                shared_initiator, responder["shared_key"],
                "混合密钥交换双方密钥不一致"
            )

    def test_different_exchanges_different_keys(self):
        """不同交换生成不同密钥"""
        init1 = self.hybrid.initiate()
        resp1 = self.hybrid.respond(init1)
        key1 = self.hybrid.finalize(init1, resp1)

        init2 = self.hybrid.initiate()
        resp2 = self.hybrid.respond(init2)
        key2 = self.hybrid.finalize(init2, resp2)

        self.assertNotEqual(key1, key2)


class TestKeyMigrationManager(unittest.TestCase):
    """密钥迁移管理器测试"""

    def setUp(self):
        self.params = PQCParams(key_rotation_seconds=1)  # 1秒轮换用于测试
        self.manager = KeyMigrationManager(self.params)

    def test_generate_key(self):
        """生成密钥"""
        record = self.manager.generate_key()
        self.assertIsInstance(record, KeyRecord)
        self.assertTrue(len(record.key_id) > 0)
        self.assertEqual(record.algorithm, self.manager.migration_phase.value)
        self.assertEqual(record.rotation_count, 0)
        self.assertFalse(record.compromised)

    def test_generate_key_with_algorithm(self):
        """指定算法生成密钥"""
        record = self.manager.generate_key(algorithm="pqc_native")
        self.assertEqual(record.algorithm, "pqc_native")

    def test_should_rotate(self):
        """密钥轮换检查"""
        record = self.manager.generate_key()
        self.assertFalse(self.manager.should_rotate(record.key_id))
        # 等待超过轮换时间
        time.sleep(1.1)
        self.assertTrue(self.manager.should_rotate(record.key_id))

    def test_rotate_key(self):
        """轮换密钥"""
        old_record = self.manager.generate_key()
        new_record = self.manager.rotate_key(old_record.key_id)
        self.assertIsNotNone(new_record)
        self.assertEqual(new_record.rotation_count, 1)
        self.assertNotEqual(new_record.key_id, old_record.key_id)

    def test_rotate_nonexistent_key(self):
        """轮换不存在的密钥"""
        result = self.manager.rotate_key("nonexistent")
        self.assertIsNone(result)

    def test_mark_compromised(self):
        """标记密钥妥协"""
        record = self.manager.generate_key()
        result = self.manager.mark_compromised(record.key_id)
        self.assertTrue(result)
        self.assertTrue(self.manager.keys[record.key_id].compromised)

    def test_mark_compromised_nonexistent(self):
        """标记不存在的密钥妥协"""
        result = self.manager.mark_compromised("nonexistent")
        self.assertFalse(result)

    def test_migrate_phase(self):
        """迁移阶段变更"""
        self.assertEqual(self.manager.migration_phase, MigrationPhase.HYBRID)
        result = self.manager.migrate_phase(MigrationPhase.PQC_NATIVE)
        self.assertTrue(result)
        self.assertEqual(self.manager.migration_phase, MigrationPhase.PQC_NATIVE)

    def test_get_migration_status(self):
        """获取迁移状态"""
        self.manager.generate_key()
        self.manager.generate_key(algorithm="classic")
        status = self.manager.get_migration_status()
        self.assertIn("current_phase", status)
        self.assertIn("total_keys", status)
        self.assertIn("keys_by_algorithm", status)
        self.assertEqual(status["total_keys"], 2)
        self.assertIn("hybrid", status["keys_by_algorithm"])
        self.assertIn("classic", status["keys_by_algorithm"])

    def test_audit_log(self):
        """审计日志记录"""
        initial_count = len(self.manager.audit_log)
        self.manager.generate_key()
        self.manager.migrate_phase(MigrationPhase.CLASSIC)
        self.assertGreater(len(self.manager.audit_log), initial_count)
        # 验证审计日志结构
        for entry in self.manager.audit_log:
            self.assertIn("timestamp", entry)
            self.assertIn("action", entry)
            self.assertIn("details", entry)


class TestPQCSecurityEvaluator(unittest.TestCase):
    """PQC 安全评估器测试"""

    def setUp(self):
        self.params = PQCParams()
        self.evaluator = PQCSecurityEvaluator(self.params)

    def test_create_evaluator(self):
        """创建评估器"""
        self.assertIsInstance(self.evaluator.kyber, KyberKEM)
        self.assertIsInstance(self.evaluator.hybrid, HybridKeyExchange)
        self.assertIsInstance(self.evaluator.migration, KeyMigrationManager)

    def test_run_algorithmic_tests(self):
        """运行算法测试"""
        results = self.evaluator.run_algorithmic_tests()
        self.assertIn("kyber_kem", results)
        self.assertIn("dilithium_signature", results)
        self.assertIn("hybrid_key_exchange", results)
        # Kyber 和混合密钥交换应通过
        self.assertTrue(results["kyber_kem"]["passed"])
        self.assertTrue(results["hybrid_key_exchange"]["passed"])

    def test_evaluate_readiness(self):
        """评估 readiness"""
        result = self.evaluator.evaluate_readiness()
        self.assertIn("pqc_readiness_score", result)
        self.assertIn("score_details", result)
        self.assertIn("algorithm_tests", result)
        self.assertIn("migration_status", result)
        self.assertIn("recommendations", result)
        self.assertGreaterEqual(result["pqc_readiness_score"], 0)
        self.assertLessEqual(result["pqc_readiness_score"], 100)
        self.assertIsInstance(result["recommendations"], list)
        self.assertGreater(len(result["recommendations"]), 0)

    def test_readiness_score_range(self):
        """readiness 评分范围"""
        result = self.evaluator.evaluate_readiness()
        score = result["pqc_readiness_score"]
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)

    def test_convenience_functions(self):
        """便捷接口函数"""
        evaluator = create_pqc_security_evaluator()
        self.assertIsInstance(evaluator, PQCSecurityEvaluator)

        result = run_pqc_self_assessment()
        self.assertIn("pqc_readiness_score", result)


class TestPQCParams(unittest.TestCase):
    """PQC 安全参数配置测试"""

    def test_default_params(self):
        """默认参数"""
        params = PQCParams()
        self.assertEqual(params.kyber_n, 256)
        self.assertEqual(params.kyber_k, 2)
        self.assertEqual(params.kyber_q, 3329)
        self.assertTrue(params.enable_classic_mix)
        self.assertEqual(params.migration_phase, "hybrid")
        self.assertEqual(params.key_rotation_seconds, 86400 * 30)

    def test_custom_params(self):
        """自定义参数"""
        params = PQCParams(
            kyber_k=4,
            enable_classic_mix=False,
            migration_phase="pqc_native",
        )
        self.assertEqual(params.kyber_k, 4)
        self.assertFalse(params.enable_classic_mix)
        self.assertEqual(params.migration_phase, "pqc_native")


if __name__ == "__main__":
    unittest.main(verbosity=2)
