#!/usr/bin/env python3
"""K8s Operator 纯函数单元测试（不需要 K8s 集群，mock kopf/kubernetes）。

验证 _build_worker_pod_template 和 _build_worker_deployment 的构造逻辑：
- 默认值正确
- 自定义 spec 正确传递
- 环境变量完整（含白名单/syscalls 条件追加）
- 安全上下文正确（runAsNonRoot, seccompProfile）
- Deployment replicas/ownerRef 正确
"""
import sys
import unittest
from unittest.mock import MagicMock

# Mock kopf 和 kubernetes，使 operator.py 可在无 K8s 环境 import
sys.modules['kopf'] = MagicMock()
sys.modules['kubernetes'] = MagicMock()
sys.modules['kubernetes.client'] = MagicMock()
sys.modules['kubernetes.config'] = MagicMock()

import importlib.util
_spec = importlib.util.spec_from_file_location("photon_operator", "operator/operator.py")
op_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(op_mod)


class TestBuildWorkerPodTemplate(unittest.TestCase):
    def test_default_values(self):
        """默认 spec 应使用模块默认值。"""
        tmpl = op_mod._build_worker_pod_template("test-pool", {})
        spec = tmpl["spec"]["containers"][0]
        self.assertEqual(spec["image"], op_mod.DEFAULT_IMAGE)
        self.assertIn("SANDBOX_POOL_NAME", [e["name"] for e in spec["env"]])
        self.assertIn("SANDBOX_RISK_LEVEL", [e["name"] for e in spec["env"]])

    def test_custom_spec(self):
        """自定义 image/risk/timeout 应正确传递。"""
        tmpl = op_mod._build_worker_pod_template("my-pool", {
            "image": "custom/sandbox:v2",
            "riskLevel": "high",
            "taskTimeoutMs": 30000,
        })
        container = tmpl["spec"]["containers"][0]
        self.assertEqual(container["image"], "custom/sandbox:v2")
        env_map = {e["name"]: e.get("value", "") for e in container["env"]}
        self.assertEqual(env_map["SANDBOX_POOL_NAME"], "my-pool")
        self.assertEqual(env_map["SANDBOX_RISK_LEVEL"], "high")
        self.assertEqual(env_map["SANDBOX_TASK_TIMEOUT_MS"], "30000")

    def test_security_context(self):
        """安全上下文应包含 runAsNonRoot 和 seccompProfile。"""
        tmpl = op_mod._build_worker_pod_template("p", {})
        sc = tmpl["spec"]["securityContext"]
        self.assertTrue(sc["runAsNonRoot"])
        self.assertEqual(sc["runAsUser"], 1000)
        self.assertEqual(sc["seccompProfile"]["type"], "RuntimeDefault")

    def test_read_whitelist_env(self):
        """readWhitelist 非空时应追加 SANDBOX_READ_WHITELIST 环境变量。"""
        tmpl = op_mod._build_worker_pod_template("p", {
            "readWhitelist": ["/tmp", "/var/log"],
        })
        env_map = {e["name"]: e.get("value", "") for e in tmpl["spec"]["containers"][0]["env"]}
        self.assertIn("SANDBOX_READ_WHITELIST", env_map)
        self.assertEqual(env_map["SANDBOX_READ_WHITELIST"], "/tmp,/var/log")

    def test_allowed_syscalls_env(self):
        """allowedSyscalls 非空时应追加 SANDBOX_ALLOWED_SYSCALLS。"""
        tmpl = op_mod._build_worker_pod_template("p", {
            "allowedSyscalls": ["read", "write", "exit"],
        })
        env_map = {e["name"]: e.get("value", "") for e in tmpl["spec"]["containers"][0]["env"]}
        self.assertIn("SANDBOX_ALLOWED_SYSCALLS", env_map)
        self.assertEqual(env_map["SANDBOX_ALLOWED_SYSCALLS"], "read,write,exit")

    def test_pod_labels(self):
        """Pod 模板应包含 app 和 pool 标签。"""
        tmpl = op_mod._build_worker_pod_template("pool-abc", {})
        labels = tmpl["metadata"]["labels"]
        self.assertEqual(labels["app"], "photon-sandbox-worker")
        self.assertEqual(labels["pool"], "pool-abc")

    def test_field_ref_env(self):
        """POD_NAME 和 POD_IP 应使用 downward API fieldRef。"""
        tmpl = op_mod._build_worker_pod_template("p", {})
        env_map = {e["name"]: e for e in tmpl["spec"]["containers"][0]["env"]}
        self.assertIn("valueFrom", env_map["POD_NAME"])
        self.assertEqual(env_map["POD_NAME"]["valueFrom"]["fieldRef"]["fieldPath"], "metadata.name")
        self.assertEqual(env_map["POD_IP"]["valueFrom"]["fieldRef"]["fieldPath"], "status.podIP")


class TestBuildWorkerDeployment(unittest.TestCase):
    def test_default_replicas(self):
        """默认 replicas=4。"""
        deploy = op_mod._build_worker_deployment("pool1", "default", {})
        self.assertEqual(deploy["spec"]["replicas"], 4)

    def test_custom_replicas(self):
        """自定义 replicas 应正确设置。"""
        deploy = op_mod._build_worker_deployment("pool1", "default", {"replicas": 10})
        self.assertEqual(deploy["spec"]["replicas"], 10)

    def test_owner_reference(self):
        """Deployment 应包含 SandboxPool ownerRef（级联删除）。"""
        deploy = op_mod._build_worker_deployment("pool1", "default", {})
        owner_refs = deploy["metadata"]["ownerReferences"]
        self.assertEqual(len(owner_refs), 1)
        self.assertEqual(owner_refs[0]["kind"], "SandboxPool")
        self.assertEqual(owner_refs[0]["name"], "pool1")
        self.assertTrue(owner_refs[0].get("controller", False))

    def test_deployment_name(self):
        """Deployment 名称应为 <pool-name>-worker。"""
        deploy = op_mod._build_worker_deployment("mypool", "ns", {})
        self.assertEqual(deploy["metadata"]["name"], "mypool-worker")
        self.assertEqual(deploy["metadata"]["namespace"], "ns")

    def test_deployment_selector_matches_template(self):
        """Deployment selector 应匹配 Pod 模板标签。"""
        deploy = op_mod._build_worker_deployment("poolx", "default", {})
        sel = deploy["spec"]["selector"]["matchLabels"]
        tmpl_labels = deploy["spec"]["template"]["metadata"]["labels"]
        for k, v in sel.items():
            self.assertEqual(tmpl_labels[k], v)


class TestCrdYamlValidity(unittest.TestCase):
    def test_crd_yaml_parseable(self):
        """deploy/crd.yaml 应可被 YAML 解析，包含 CRD 和示例 CR。"""
        import yaml
        with open("deploy/crd.yaml") as f:
            docs = list(yaml.safe_load_all(f))
        self.assertGreaterEqual(len(docs), 2)
        kinds = [d["kind"] for d in docs if d]
        self.assertIn("CustomResourceDefinition", kinds)
        self.assertIn("SandboxPool", kinds)

    def test_crd_group_version(self):
        """CRD 应使用 sandbox.photon.io 组和 v1 版本。"""
        import yaml
        with open("deploy/crd.yaml") as f:
            docs = list(yaml.safe_load_all(f))
        crd = next(d for d in docs if d and d["kind"] == "CustomResourceDefinition")
        self.assertEqual(crd["spec"]["group"], "sandbox.photon.io")
        versions = [v["name"] for v in crd["spec"]["versions"]]
        self.assertTrue(any(v.startswith("v1") for v in versions), f"versions={versions}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
