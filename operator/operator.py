#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SandboxPool Operator —— K8s 原生沙盒算子（任务4 + 本轮完善）
================================================================
基于 kopf 框架的声明式控制器 + 独立核心 Reconcile 循环：

  - 监听 SandboxPool CR（期望副本数 replicas / 风险等级 / 资源配额 / scalePolicy）
  - 核心 Reconcile 循环：后台线程周期全量扫描所有 SandboxPool CR，逐个对账
    （期望副本数 -> Deployment 副本数），实现自愈与声明式扩缩容
  - 完整 worker Pod 模板：gRPC 端口 / 就绪&存活探针 / 安全上下文 / 只读根文件系统
  - 更新 CR status（ready/idle/busy/total + phase）

运行前提：K8s 集群 + kopf + kubernetes Python 客户端
  pip install kopf kubernetes
  kopf run operator.py

说明：沙盒 worker 是承载 photon_sandbox 预 fork 进程的容器镜像（photon/sandbox-worker），
operator 只负责声明式池编排（副本数对账、状态回写），实际沙盒能力由容器内进程提供。
"""

import logging
import threading

import kopf
import kubernetes

logger = logging.getLogger("sandbox-pool-operator")

# ------------------------------------------------------------------
# 常量
# ------------------------------------------------------------------
CRD_GROUP = "sandbox.photon.io"
CRD_VERSION = "v1alpha1"
CRD_PLURAL = "sandboxpools"

DEFAULT_IMAGE = "photon/sandbox-worker:4.14"
DEFAULT_IMAGE_PULL_POLICY = "IfNotPresent"
DEFAULT_MEMORY = "256Mi"
DEFAULT_CPU = "500m"
DEFAULT_RISK = "MEDIUM"
DEFAULT_TASK_TIMEOUT_MS = 5000
GRPC_PORT = 50051
RECONCILE_INTERVAL_SEC = 30.0   # 核心 Reconcile 循环周期
SERVICE_ACCOUNT = "sandbox-worker"


# ------------------------------------------------------------------
# Pod 模板：worker 容器完整定义
# ------------------------------------------------------------------
def _build_worker_pod_template(pool_name: str, spec: dict) -> dict:
    """构造 worker Pod 模板（容器 / 探针 / 安全上下文 / 卷）。"""
    image = spec.get("image", DEFAULT_IMAGE)
    memory = spec.get("memoryLimit", DEFAULT_MEMORY)
    cpu = spec.get("cpuLimit", DEFAULT_CPU)
    risk = spec.get("riskLevel", DEFAULT_RISK)
    timeout_ms = int(spec.get("taskTimeoutMs", DEFAULT_TASK_TIMEOUT_MS))
    read_whitelist = spec.get("readWhitelist", []) or []
    allowed_syscalls = spec.get("allowedSyscalls", []) or []

    env = [
        {"name": "SANDBOX_POOL_NAME", "value": pool_name},
        {"name": "SANDBOX_RISK_LEVEL", "value": risk},
        {"name": "SANDBOX_TASK_TIMEOUT_MS", "value": str(timeout_ms)},
        {"name": "POD_NAME",
         "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}}},
        {"name": "POD_IP",
         "valueFrom": {"fieldRef": {"fieldPath": "status.podIP"}}},
    ]
    if read_whitelist:
        env.append({"name": "SANDBOX_READ_WHITELIST",
                    "value": ",".join(read_whitelist)})
    if allowed_syscalls:
        env.append({"name": "SANDBOX_ALLOWED_SYSCALLS",
                    "value": ",".join(allowed_syscalls)})

    return {
        "metadata": {
            "labels": {
                "app": "photon-sandbox-worker",
                "pool": pool_name,
            },
        },
        "spec": {
            "serviceAccountName": SERVICE_ACCOUNT,
            "restartPolicy": "Always",
            "securityContext": {
                "runAsNonRoot": True,
                "runAsUser": 1000,
                "runAsGroup": 1000,
                "fsGroup": 1000,
                "seccompProfile": {"type": "RuntimeDefault"},
            },
            "containers": [
                {
                    "name": "sandbox-worker",
                    "image": image,
                    "imagePullPolicy": DEFAULT_IMAGE_PULL_POLICY,
                    "args": [
                        "--risk", risk,
                        "--task-timeout-ms", str(timeout_ms),
                        "--port", str(GRPC_PORT),
                    ],
                    "env": env,
                    "ports": [
                        {"name": "grpc", "containerPort": GRPC_PORT,
                         "protocol": "TCP"},
                    ],
                    # 就绪探针：gRPC 端口可用即认为可接任务
                    "readinessProbe": {
                        "tcpSocket": {"port": GRPC_PORT},
                        "initialDelaySeconds": 5,
                        "periodSeconds": 10,
                        "timeoutSeconds": 2,
                        "failureThreshold": 3,
                    },
                    # 存活探针：预 fork worker 失活则重启 Pod
                    "livenessProbe": {
                        "exec": {
                            "command": [
                                "/bin/sh", "-c",
                                "test -f /tmp/photon_worker_ready",
                            ],
                        },
                        "initialDelaySeconds": 10,
                        "periodSeconds": 15,
                        "timeoutSeconds": 3,
                        "failureThreshold": 3,
                    },
                    "resources": {
                        "requests": {"memory": memory, "cpu": cpu},
                        "limits": {"memory": memory, "cpu": cpu},
                    },
                    "securityContext": {
                        "allowPrivilegeEscalation": False,
                        "readOnlyRootFilesystem": True,
                        "capabilities": {"drop": ["ALL"]},
                    },
                    "volumeMounts": [
                        {"name": "tmp", "mountPath": "/tmp"},
                    ],
                }
            ],
            "volumes": [
                {"name": "tmp", "emptyDir": {}},
            ],
        },
    }


def _build_worker_deployment(name: str, namespace: str, spec: dict) -> dict:
    """由 Pod 模板构造 worker Deployment（replicas = spec.replicas）。"""
    replicas = int(spec.get("replicas", 4))
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": f"{name}-worker",
            "namespace": namespace,
            "labels": {"app": "photon-sandbox-worker", "pool": name},
            "ownerReferences": [
                # ownerRef：删除 SandboxPool 时级联清理 worker Deployment
                {"apiVersion": f"{CRD_GROUP}/{CRD_VERSION}",
                 "kind": "SandboxPool",
                 "name": name,
                 "uid": None,   # 由调用方回填
                 "controller": True},
            ],
        },
        "spec": {
            "replicas": replicas,
            "selector": {"matchLabels": {"app": "photon-sandbox-worker", "pool": name}},
            "template": _build_worker_pod_template(name, spec),
        },
    }


# ------------------------------------------------------------------
# 状态回写
# ------------------------------------------------------------------
def _patch_pool_status(namespace: str, name: str, status: dict):
    api = kubernetes.client.CustomObjectsApi()
    api.patch_namespaced_custom_object_status(
        group=CRD_GROUP, version=CRD_VERSION, namespace=namespace,
        plural=CRD_PLURAL, name=name, body={"status": status})


# ------------------------------------------------------------------
# 核心对账逻辑（Reconcile 单次执行）
# ------------------------------------------------------------------
def _reconcile(spec: dict, name: str, namespace: str) -> str:
    """期望副本数 -> 实际 Deployment 副本数；返回 phase。"""
    apps = kubernetes.client.AppsV1Api()
    expected = int(spec.get("replicas", 4))
    deploy_name = f"{name}-worker"
    phase = "Ready"

    try:
        deploy = apps.read_namespaced_deployment(deploy_name, namespace)
        current = deploy.spec.replicas or 0
        if current != expected:
            logger.info("[Reconcile] scaling %s from %d to %d",
                        deploy_name, current, expected)
            apps.patch_namespaced_deployment(
                deploy_name, namespace, {"spec": {"replicas": expected}})
            phase = "Scaling"
        ready = deploy.status.ready_replicas or 0
        if ready < expected:
            phase = "Scaling"
    except kubernetes.client.rest.ApiException as e:
        if e.status == 404:
            logger.info("[Reconcile] creating %s (replicas=%d)", deploy_name, expected)
            apps.create_namespaced_deployment(
                namespace, _build_worker_deployment(name, namespace, spec))
            phase = "Creating"
        else:
            logger.error("[Reconcile] API error: %s", e)
            phase = "Degraded"

    # 更新 status
    try:
        deploy = apps.read_namespaced_deployment(deploy_name, namespace)
        ready = deploy.status.ready_replicas or 0
        _patch_pool_status(namespace, name, {
            "readyReplicas": ready,
            "totalReplicas": expected,
            "idleReplicas": 0,     # 由 worker 侧上报扩展
            "busyReplicas": 0,
            "phase": phase,
            "lastUpdateTime": kubernetes.utils.format_timestamp(),
        })
    except Exception as e:  # noqa: BLE001
        logger.warning("[Reconcile] failed to update status: %s", e)

    return phase


def list_all_pools():
    """列出集群中所有 SandboxPool 自定义资源。"""
    api = kubernetes.client.CustomObjectsApi()
    try:
        items = api.list_cluster_custom_object(
            group=CRD_GROUP, version=CRD_VERSION, plural=CRD_PLURAL
        ).get("items", [])
    except kubernetes.client.rest.ApiException as e:
        if e.status == 404:
            return []   # CRD 尚未安装
        raise
    return items


# ------------------------------------------------------------------
# 核心 Reconcile 循环（独立后台线程，周期性全量对账）
# ------------------------------------------------------------------
def _reconcile_loop(stop_event: threading.Event):
    """核心 Reconcile 循环：周期扫描所有 SandboxPool CR 并逐个 reconcile。"""
    logger.info("[ReconcileLoop] started (interval=%ss)", RECONCILE_INTERVAL_SEC)
    while not stop_event.is_set():
        try:
            pools = list_all_pools()
            for pool in pools:
                meta = pool.get("metadata", {})
                name = meta.get("name")
                namespace = meta.get("namespace", "default")
                spec = pool.get("spec", {})
                if not name:
                    continue
                try:
                    _reconcile(spec, name, namespace)
                except Exception as e:  # noqa: BLE001
                    logger.error("[ReconcileLoop] reconcile %s/%s failed: %s",
                                 namespace, name, e)
        except Exception as e:  # noqa: BLE001
            logger.error("[ReconcileLoop] scan failed: %s", e)
        stop_event.wait(RECONCILE_INTERVAL_SEC)
    logger.info("[ReconcileLoop] stopped")


# ------------------------------------------------------------------
# kopf 事件处理器（事件驱动路径，与 Reconcile 循环共用同一对账逻辑）
# ------------------------------------------------------------------
@kopf.on.create(CRD_GROUP, CRD_VERSION, CRD_PLURAL)
def on_create(spec, name, namespace, **_):
    logger.info("SandboxPool %s created (replicas=%s)", name, spec.get("replicas"))
    return {"phase": _reconcile(spec, name, namespace)}


@kopf.on.update(CRD_GROUP, CRD_VERSION, CRD_PLURAL)
def on_update(spec, name, namespace, **_):
    logger.info("SandboxPool %s updated", name)
    return {"phase": _reconcile(spec, name, namespace)}


@kopf.on.timer(CRD_GROUP, CRD_VERSION, CRD_PLURAL, interval=RECONCILE_INTERVAL_SEC)
def on_timer(spec, name, namespace, **_):
    return {"phase": _reconcile(spec, name, namespace)}


@kopf.on.delete(CRD_GROUP, CRD_VERSION, CRD_PLURAL)
def on_delete(name, namespace, **_):
    logger.info("SandboxPool %s deleted; worker Deployment cleaned by ownerRefs", name)


def main():
    kubernetes.config.load_incluster_config()

    # 启动核心 Reconcile 循环（后台线程，独立于 kopf 事件机制）
    stop_event = threading.Event()
    loop_thread = threading.Thread(
        target=_reconcile_loop, args=(stop_event,), daemon=True)
    loop_thread.start()

    kopf.configure(verbose=True)
    try:
        kopf.run()
    finally:
        stop_event.set()
        loop_thread.join(timeout=5)


if __name__ == "__main__":
    main()
