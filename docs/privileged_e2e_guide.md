# 特权环境端到端验证手册

本文档说明如何在有 root 权限的 Linux 机器上完整跑通 CRIU、eBPF、K8s Operator 端到端流程。

## 环境要求
- Linux kernel >= 5.9（close_range）>= 5.10（eBPF cgroup）
- root 权限（sudo）
- Ubuntu 22.04 / Debian 12 / CentOS Stream 9+
- 至少 2CPU / 4GB RAM

---

## 一、CRIU 进程级快照端到端

### 1.1 安装 CRIU
```bash
sudo apt update
sudo apt install -y criu
# 验证
criu --version
# 检查内核支持
sudo criu check --all
```

### 1.2 验证 CRIU dump/restore
```bash
# 启动一个测试进程
sleep 300 &
PID=$!
echo "Test PID: $PID"

# dump（保存进程状态）
sudo mkdir -p /tmp/criu_test
sudo criu dump -t $PID -D /tmp/criu_test --shell-job --leave-running
echo "Dump exit code: $?"
ls -la /tmp/criu_test/

# 杀掉原进程
kill $PID

# restore（从快照恢复）
sudo criu restore -d -D /tmp/criu_test --shell-job --pidfile /tmp/criu_test/restored.pid
echo "Restore exit code: $?"
cat /tmp/criu_test/restored.pid
ps aux | grep sleep
```

### 1.3 集成到沙盒工程
```bash
cd photon_kernel_sil3_v414
# 编译（含 CRIU 测试）
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j4

# 运行 CRIU 测试（有 criu 时不会跳过）
./build/test_enhanced --gtest_filter='*Criu*:*Snapshot*'
```

### 1.4 预期结果
- `criu check --all` 全部通过
- dump 生成 inventory.img、pages-*.img 等文件
- restore 后进程恢复运行，PID 与原进程不同
- CRIU 单元测试全部通过（不再跳过）

---

## 二、eBPF 出口流量白名单端到端

### 2.1 安装依赖
```bash
sudo apt install -y libbpf-dev clang llvm linux-headers-$(uname -r)
# 验证内核支持
zcat /proc/config.gz 2>/dev/null | grep -E 'CONFIG_BPF|CONFIG_CGROUP_BPF' || \
  grep -E 'CONFIG_BPF|CONFIG_CGROUP_BPF' /boot/config-$(uname -r)
```

### 2.2 验证 eBPF 加载
```bash
# 检查权限
sudo capsh --print | grep -E 'cap_bpf|cap_net_admin'

# 测试加载最小 eBPF 程序
cat > /tmp/min_bpf.c << 'EOF'
#include <linux/bpf.h>
int main() { return 0; }
EOF
# 用 bpftool 验证
sudo bpftool version 2>/dev/null || sudo apt install -y bpftool
```

### 2.3 编译并加载 eBPF 网络过滤程序
```bash
cd photon_kernel_sil3_v414
# eBPF 程序（出口流量白名单）
cat > /tmp/network_filter.bpf.c << 'EOF'
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/in.h>
#include <linux/tcp.h>

// 白名单 map：key=ip+port, value=1(allow)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);  // 简化：只按 IP 白名单
    __type(value, __u8);
} allowlist SEC(".maps");

SEC("cgroup/skb")
int egress_filter(struct __sk_buff *skb) {
    // 只过滤出口流量
    if (skb->pkt_type != PACKET_OUTGOING) return 1; // allow
    // 查白名单（简化：默认 deny）
    __u32 key = 0; // 实际应从 skb->remote_ip4 提取
    __u8 *allow = bpf_map_lookup_elem(&allowlist, &key);
    if (allow && *allow) return 1; // allow
    return 0; // drop
}
char _license[] SEC("license") = "GPL";
EOF

# 编译 eBPF 程序
clang -O2 -target bpf -c /tmp/network_filter.bpf.c -o /tmp/network_filter.bpf.o

# 加载到 cgroup
sudo mkdir -p /sys/fs/cgroup/test_sandbox
CGROUP_FD=$(sudo cat /sys/fs/cgroup/test_sandbox/cgroup.procs 2>/dev/null; echo $?)
sudo bpftool cgroup attach /sys/fs/cgroup/test_sandbox egress pinned /tmp/network_filter.o 2>/dev/null || \
echo "使用 libbpf 加载器加载"
```

### 2.4 集成到沙盒工程
```bash
# 编译（含 eBPF 测试）
cmake -B build -DCMAKE_BUILD_TYPE=Release -DPHOTON_ENABLE_EBPF=ON
cmake --build build -j4

# 运行 eBPF 测试（有 CAP_BPF 时不会降级）
sudo ./build/test_enhanced --gtest_filter='*Ebpf*'
```

### 2.5 验证白名单生效
```bash
# 添加白名单规则（允许 8.8.8.8:443）
# 通过 EbpfNetworkEnforcer::add_rule API
# 验证：白名单内 IP 可访问，白名单外 IP 被丢弃
```

---

## 三、K8s Operator 端到端

### 3.1 安装 K8s 测试集群
```bash
# 安装 kind
[ $(uname -m) = x86_64 ] && curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/

# 创建集群
kind create cluster --name sandbox-test

# 安装 kubectl
sudo apt install -y kubectl

# 验证
kubectl cluster-info
kubectl get nodes
```

### 3.2 安装 Operator 依赖
```bash
pip3 install kopf kubernetes
```

### 3.3 部署 CRD
```bash
cd photon_kernel_sil3_v414
kubectl apply -f deploy/crd.yaml
# 验证 CRD 已注册
kubectl get crd sandboxpools.sandbox.photon.io
```

### 3.4 启动 Operator
```bash
# 终端1：启动 Operator
kopf run operator/operator.py --verbose

# 终端2：创建 SandboxPool CR
cat << 'EOF' | kubectl apply -f -
apiVersion: sandbox.photon.io/v1alpha1
kind: SandboxPool
metadata:
  name: test-pool
spec:
  replicas: 3
  riskLevel: medium
  memoryLimit: 256Mi
  cpuLimit: 500m
  image: photonkernel/sandbox-worker:latest
EOF
```

### 3.5 验证 Reconcile
```bash
# 查看 SandboxPool
kubectl get sandboxpools
kubectl describe sandboxpool test-pool

# 查看 Operator 创建的 Deployment
kubectl get deployments
kubectl get pods -l app=photon-sandbox-worker

# 验证副本数
kubectl get deployment test-pool-worker -o jsonpath='{.spec.replicas}'
# 应输出 3

# 扩缩容测试
kubectl patch sandboxpool test-pool -p '{"spec":{"replicas":5}}'
sleep 3
kubectl get pods -l app=photon-sandbox-worker
# 应变为 5 个

# 删除测试
kubectl delete sandboxpool test-pool
kubectl get deployments
# Deployment 应被级联删除
```

### 3.6 预期结果
- CRD 注册成功
- Operator 启动后监听 SandboxPool 事件
- 创建 SandboxPool CR 后，Operator 创建对应 Deployment
- Deployment replicas 与 spec.replicas 一致
- 扩缩容后 Pod 数量相应变化
- 删除 SandboxPool CR 后 Deployment 被级联删除

---

## 四、gRPC 服务端端到端

### 4.1 安装 gRPC 依赖
```bash
sudo apt update
sudo apt install -y protobuf-compiler libprotobuf-dev libgrpc++-dev protobuf-compiler-grpc
```

### 4.2 编译 gRPC 服务端
```bash
cd photon_kernel_sil3_v414
cmake -B build -DCMAKE_BUILD_TYPE=Release -DPHOTON_ENABLE_GRPC=ON
cmake --build build -j4
```

### 4.3 启动服务端和客户端
```bash
# 终端1：启动 gRPC 服务端（预热池 min=10）
./build/sandbox_server

# 终端2：运行客户端
./build/sandbox_client
# 应输出：Execute Python print(42) -> output=42, RTT=xxxms
```

### 4.4 验证异步任务
```bash
# 使用 grpcurl 或自定义客户端测试 ExecuteAsync + GetTaskResult
grpcurl -plaintext -d '{"task_code":"import time; time.sleep(1); print(\"async done\")","runner":0}' \
  localhost:50051 photon.sandbox.SandboxService/ExecuteAsync
# 返回 task_id
grpcurl -plaintext -d '{"task_id":"async-1"}' \
  localhost:50051 photon.sandbox.SandboxService/GetTaskResult
# 等待1秒后查询，应返回 completed=true, output="async done"
```

---

## 五、全链路验证清单

| 组件 | 验证命令 | 预期结果 |
|---|---|---|
| CRIU | `sudo criu check --all` | 全部 pass |
| CRIU dump/restore | 手动 dump/restore sleep 进程 | 进程恢复运行 |
| eBPF | `sudo bpftool prog show` | 有 eBPF 程序加载 |
| eBPF 白名单 | 白名单外 IP 被丢弃 | ping 不通 |
| K8s CRD | `kubectl get crd` | sandboxpools 存在 |
| K8s Reconcile | `kubectl get pods` | replicas 与 spec 一致 |
| K8s 扩缩容 | patch replicas | Pod 数量变化 |
| gRPC 服务端 | `./sandbox_client` | output=42, RTT<10ms |
| gRPC 异步 | ExecuteAsync + GetTaskResult | completed=true |
| 安全审计 | `./build/test_enhanced` | 77+ 测试通过 |
| 模糊测试 | 运行 fuzz harness 60秒 | 无 crash/asan 报错 |
