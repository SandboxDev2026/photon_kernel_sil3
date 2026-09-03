# 第三方安全审计测试用例集（第十七条）

**版本**: v1.0
**适用范围**: PhotonBox 沙盒集群（LightPool + StrongPool）
**规范依据**: 第十七条（独立第三方安全审计）
**用途**: 交付给外部审计机构的具体测试用例，包含测试步骤、预期结果、验证方法

---

## 1. 沙盒逃逸测试用例

### ESC-001: Namespace 逃逸 - mount namespace 突破

**测试目的**: 验证沙盒进程无法突破 mount namespace 访问宿主机文件系统

**测试步骤**:
```bash
# 在沙盒内执行
# 1. 尝试重新挂载 /proc
mount -t proc proc /proc 2>&1

# 2. 尝试通过 /proc/self/root 访问宿主机根目录
ls -la /proc/self/root/ 2>&1

# 3. 尝试 pivot_root 到宿主机目录
mkdir /tmp/host_root
pivot_root /tmp/host_root /tmp/host_root/old 2>&1

# 4. 尝试通过符号链接访问宿主机
ln -s / /tmp/host_link
ls -la /tmp/host_link/etc/shadow 2>&1
```

**预期结果**:
- 所有操作均失败，返回 Permission denied 或 Operation not permitted
- 无法读取宿主机 /etc/shadow、/root 等敏感文件
- 无法重新挂载 /proc

**验证方法**:
- 检查沙盒内是否能看到宿主机进程（ps aux 应只看到沙盒内进程）
- 检查是否能读取宿主机文件内容

**严重级别**: P0

---

### ESC-002: seccomp 绕过 - ptrace 注入

**测试目的**: 验证 seccomp 过滤器能阻止 ptrace 系统调用，防止进程注入

**测试步骤**:
```c
// 在沙盒内编译并执行
#include <sys/ptrace.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

int main() {
    // 尝试 ptrace 附加到自身
    long ret = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    printf("ptrace return: %ld\\n", ret);
    if (ret == 0) {
        printf("VULNERABLE: ptrace allowed!\\n");
        return 1;
    }
    printf("SAFE: ptrace blocked\\n");
    return 0;
}
```

**预期结果**:
- ptrace 调用返回 -1，errno 为 EPERM
- 进程被 seccomp 杀死或返回错误
- 输出 "SAFE: ptrace blocked"

**验证方法**:
- 检查 seccomp 配置中是否包含 ptrace 系统调用的禁止规则
- 检查 dmesg 中是否有 seccomp 拦截日志

**严重级别**: P0

---

### ESC-003: Landlock 绕过 - 路径遍历攻击

**测试目的**: 验证 Landlock 路径规则能阻止路径遍历攻击

**测试步骤**:
```bash
# 在沙盒内执行
# 1. 相对路径遍历
cat ../../../../etc/shadow 2>&1

# 2. 绝对路径访问
cat /etc/shadow 2>&1

# 3. 符号链接绕过
ln -s /etc/shadow /tmp/link_to_shadow
cat /tmp/link_to_shadow 2>&1

# 4. 硬链接绕过
ln /etc/shadow /tmp/hard_link 2>&1

# 5. 编码绕过
cat $(printf '/etc/shadow') 2>&1
cat /etc/./shadow 2>&1
cat /etc//shadow 2>&1
```

**预期结果**:
- 所有路径访问均失败，返回 Permission denied
- 无法通过符号链接、硬链接、路径编码绕过限制
- 无法读取 /etc/shadow 内容

**验证方法**:
- 检查 Landlock 规则是否覆盖所有路径访问方式
- 检查是否有遗漏的路径（如 /proc、/sys）

**严重级别**: P0

---

### ESC-004: VM 逃逸 - virtio 设备攻击（StrongPool）

**测试目的**: 验证 Firecracker MicroVM 无法通过 virtio 设备攻击逃逸到宿主机

**测试步骤**:
```bash
# 在 VM 内执行
# 1. 检查 virtio 设备
ls -la /dev/vd* /dev/vhost-* 2>&1

# 2. 尝试直接访问 virtio 队列
# （需要编写内核模块或使用已知 CVE POC）

# 3. 尝试通过 vsock 访问宿主机服务
nc -U /dev/vsock 2>&1

# 4. 检查是否能看到宿主机进程
ps aux | head -20

# 5. 尝试加载恶意内核模块
insmod malicious.ko 2>&1
```

**预期结果**:
- 无法通过 virtio 设备访问宿主机内存
- vsock 只能连接到预定义的服务端口
- 无法看到宿主机进程
- 无法加载未签名的内核模块（如果启用了 Secure Boot）

**验证方法**:
- 使用 Firecracker 已知 CVE POC 进行测试（如 CVE-2023-41051）
- 检查 VM 内是否能访问宿主机文件系统

**严重级别**: P0

---

### ESC-005: 内核漏洞利用 - CVE-2024-1086 nf_tables 逃逸

**测试目的**: 验证沙盒能防御已知内核漏洞利用

**测试步骤**:
```bash
# 在沙盒内执行 CVE-2024-1086 POC
# （POC 代码从公开渠道获取，此处省略具体利用代码）

# 1. 检查内核版本
uname -r

# 2. 检查是否有 CAP_NET_ADMIN
capsh --print 2>&1 | grep -i net_admin

# 3. 尝试创建 nftables 规则
nft list ruleset 2>&1

# 4. 执行 POC（如果环境允许）
./cve-2024-1086-poc 2>&1
```

**预期结果**:
- 如果内核版本 < 6.6.11，POC 可能成功逃逸 → 必须升级内核
- 如果内核版本 >= 6.6.11，POC 失败
- 沙盒内应无 CAP_NET_ADMIN，无法创建 nftables 规则

**验证方法**:
- 检查宿主机内核版本是否 >= 6.6.11
- 检查沙盒内是否有 CAP_NET_ADMIN
- 执行 POC 验证是否能逃逸

**严重级别**: P0

---

## 2. 权限提升测试用例

### PRI-001: 容器内提权 - SUID 二进制利用

**测试目的**: 验证沙盒内无可用的 SUID 二进制进行提权

**测试步骤**:
```bash
# 在沙盒内执行
# 1. 查找所有 SUID 二进制
find / -perm -4000 -type f 2>/dev/null

# 2. 检查常见提权 SUID 二进制
ls -la /usr/bin/sudo /usr/bin/su /bin/ping /usr/bin/newgrp 2>&1

# 3. 尝试使用 sudo
sudo -i 2>&1

# 4. 尝试使用 su
su root 2>&1

# 5. 检查是否有可写的 SUID 二进制
find / -perm -4000 -writable -type f 2>/dev/null
```

**预期结果**:
- 无 SUID 二进制，或 SUID 二进制无法用于提权
- sudo/su 不可用或无法提权
- 无可写的 SUID 二进制

**验证方法**:
- 检查沙盒 rootfs 构建脚本中是否删除了所有 SUID 二进制
- 检查是否使用了最小化 rootfs

**严重级别**: P0

---

### PRI-002: Capability 残留检查

**测试目的**: 验证沙盒进程无残留的高危 capabilities

**测试步骤**:
```bash
# 在沙盒内执行
# 1. 检查当前进程 capabilities
cat /proc/self/status | grep -i cap

# 2. 使用 capsh 检查
capsh --print 2>&1

# 3. 检查是否有高危 capability
# CAP_SYS_ADMIN, CAP_NET_ADMIN, CAP_SYS_PTRACE, CAP_DAC_OVERRIDE 等
cat /proc/self/status | grep CapEff
```

**预期结果**:
- CapEff 应为 0000000000000000（无 capabilities）
- 或仅包含必要的非高危 capabilities
- 无 CAP_SYS_ADMIN、CAP_NET_ADMIN、CAP_SYS_PTRACE 等高危 capability

**验证方法**:
- 检查沙盒启动代码中是否调用了 cap_drop(CAP_ALL)
- 检查是否有遗漏的 capability

**严重级别**: P0

---

### PRI-003: 解释器白名单绕过

**测试目的**: 验证解释器路径白名单是内核强制的，无法通过应用层逻辑绕过

**测试步骤**:
```bash
# 在沙盒内执行
# 1. 尝试执行非白名单解释器
/usr/bin/perl -e 'print "hello\\n"' 2>&1
/usr/bin/ruby -e 'print "hello\\n"' 2>&1
/bin/sh -c 'echo hello' 2>&1

# 2. 尝试通过符号链接绕过
ln -s /usr/bin/python3 /tmp/fake_python
/tmp/fake_python -c 'print("hello")' 2>&1

# 3. 尝试通过硬链接绕过
ln /usr/bin/python3 /tmp/hard_python 2>&1

# 4. 尝试通过环境变量绕过
PYTHONPATH=/tmp python3 -c 'print("hello")' 2>&1

# 5. 尝试直接执行二进制
./custom_binary 2>&1
```

**预期结果**:
- 非白名单解释器执行失败，返回 Permission denied
- 无法通过符号链接、硬链接绕过白名单
- 白名单是通过 Landlock/seccomp 在内核层强制的，不是应用层判断

**验证方法**:
- 检查白名单实现是 Landlock 规则还是 seccomp 规则
- 检查是否有应用层判断的绕过面

**严重级别**: P0

---

## 3. 数据泄露测试用例

### LEAK-001: 宿主机 /proc 信息泄露

**测试目的**: 验证沙盒进程无法通过 /proc 获取宿主机信息

**测试步骤**:
```bash
# 在沙盒内执行
# 1. 检查 /proc 中是否有宿主机进程
ls /proc/ | grep -E '^[0-9]+$' | wc -l
ps aux | wc -l

# 2. 尝试读取宿主机进程信息
cat /proc/1/status 2>&1
cat /proc/sched_debug 2>&1

# 3. 尝试读取宿主机内核信息
cat /proc/kallsyms 2>&1 | head -5
cat /proc/modules 2>&1

# 4. 尝试读取宿主机内存
cat /dev/mem 2>&1 | head -5
cat /proc/kcore 2>&1 | head -5

# 5. 检查是否能看到宿主机 PID
echo "PID 1: $(cat /proc/1/comm 2>&1)"
```

**预期结果**:
- /proc 中只有沙盒内的进程（PID namespace 隔离）
- 无法读取宿主机进程信息
- /proc/kallsyms 全为 0 或不可读
- 无法读取 /dev/mem、/proc/kcore

**验证方法**:
- 检查是否启用了 PID namespace
- 检查 /proc 是否被正确挂载（hidepid=2 等）

**严重级别**: P0

---

### LEAK-002: 其他沙盒实例文件访问

**测试目的**: 验证沙盒实例之间完全隔离，无法互相访问文件

**测试步骤**:
```bash
# 在沙盒 A 内创建测试文件
echo "secret_data_from_A" > /tmp/secret_A.txt
chmod 644 /tmp/secret_A.txt

# 在沙盒 B 内尝试访问沙盒 A 的文件
# 1. 通过共享内存
ls -la /dev/shm/ 2>&1
cat /dev/shm/secret_A.txt 2>&1

# 2. 通过 /tmp（如果共享）
cat /tmp/secret_A.txt 2>&1

# 3. 通过进程间通信
ipcs 2>&1

# 4. 通过网络（localhost）
nc -zv 127.0.0.1 1-1000 2>&1 | grep succeeded
```

**预期结果**:
- 无法访问其他沙盒实例的文件
- /dev/shm、/tmp 等目录是独立的
- IPC 是隔离的
- 网络 localhost 只能访问自身服务

**验证方法**:
- 检查是否启用了 mount namespace
- 检查是否有共享目录被挂载到多个沙盒

**严重级别**: P0

---

### LEAK-003: HMAC 密钥泄露检查

**测试目的**: 验证审计 HMAC 密钥不会泄露到沙盒进程内存中

**测试步骤**:
```bash
# 在沙盒内执行
# 1. 检查环境变量中是否有密钥
env | grep -iE 'key|secret|hmac|token' 2>&1

# 2. 检查进程内存中是否有密钥（需要 root）
# cat /proc/self/maps | head -20
# grep -a 'secret_key' /proc/self/mem 2>&1

# 3. 检查配置文件中是否有硬编码密钥
find / -name '*.conf' -o -name '*.yaml' -o -name '*.json' 2>/dev/null | xargs grep -l 'key\|secret' 2>/dev/null

# 4. 检查是否能访问宿主机密钥文件
cat /etc/ssl/private/key.pem 2>&1
cat /root/.ssh/id_rsa 2>&1
```

**预期结果**:
- 环境变量中无密钥
- 沙盒进程内存中无 HMAC 密钥
- 配置文件中无硬编码密钥
- 无法访问宿主机密钥文件

**验证方法**:
- 检查密钥管理代码，确认密钥通过外部注入，不硬编码
- 检查密钥是否只在控制器进程中，不传递给沙盒 worker

**严重级别**: P0

---

## 4. 网络隔离测试用例

### NET-001: 内网服务访问拦截

**测试目的**: 验证 eBPF 网络过滤能拦截内网 RFC1918 地址访问

**测试步骤**:
```bash
# 在沙盒内执行
# 1. 尝试访问 10.0.0.0/8 网段
curl -v --connect-timeout 2 http://10.0.0.1/ 2>&1
ping -c 1 -W 2 10.0.0.1 2>&1

# 2. 尝试访问 172.16.0.0/12 网段
curl -v --connect-timeout 2 http://172.16.0.1/ 2>&1

# 3. 尝试访问 192.168.0.0/16 网段
curl -v --connect-timeout 2 http://192.168.0.1/ 2>&1

# 4. 尝试访问 127.0.0.0/8（除了自身）
curl -v --connect-timeout 2 http://127.0.0.2/ 2>&1

# 5. 尝试访问链路本地地址
curl -v --connect-timeout 2 http://169.254.0.1/ 2>&1
```

**预期结果**:
- 所有内网地址访问均被 eBPF 拦截，返回 Connection refused 或 Operation not permitted
- 169.254.169.254（云元数据）被拦截
- 审计日志记录所有内网访问尝试

**验证方法**:
- 检查 eBPF 程序是否加载成功
- 检查 eBPF 规则是否包含所有 RFC1918 网段
- 检查审计日志是否记录拦截事件

**严重级别**: P0

---

### NET-002: DNS 隧道绕过检测

**测试目的**: 验证沙盒无法通过自定义 DNS 服务器绕过域名白名单

**测试步骤**:
```bash
# 在沙盒内执行
# 1. 尝试修改 /etc/resolv.conf
echo "nameserver 8.8.8.8" > /etc/resolv.conf 2>&1
cat /etc/resolv.conf

# 2. 尝试使用自定义 DNS 服务器解析
nslookup evil.com 8.8.8.8 2>&1
dig @8.8.8.8 evil.com 2>&1

# 3. 尝试通过 DNS 隧道传输数据
# 使用 dnscat2 或 iodine 等工具（如果可用）

# 4. 尝试直接访问 IP 绕过域名白名单
curl -v --connect-timeout 2 http://1.2.3.4/ 2>&1

# 5. 尝试使用 HTTPS 直接访问 IP
curl -vk --connect-timeout 2 https://1.2.3.4/ 2>&1
```

**预期结果**:
- 无法修改 /etc/resolv.conf（只读挂载）
- DNS 请求被强制劫持到隔离网关 DNS
- 无法通过 DNS 隧道传输数据
- 直接 IP 访问被 eBPF 内网黑名单拦截（如果是内网 IP）

**验证方法**:
- 检查 /etc/resolv.conf 是否为只读
- 检查隔离网关是否强制 DNS 劫持
- 检查 eBPF 是否拦截非白名单域名的 IP

**严重级别**: P0

---

## 5. 审计完整性测试用例

### AUD-001: 审计日志防篡改验证

**测试目的**: 验证 HMAC 哈希链能检测审计日志篡改

**测试步骤**:
```bash
# 1. 获取当前审计日志
cp /var/log/photon/audit.log /tmp/audit_original.log

# 2. 计算原始哈希链
python3 -c "
import json, hmac, hashlib
with open('/tmp/audit_original.log') as f:
    records = [json.loads(line) for line in f if line.strip()]
print(f'Total records: {len(records)}')
print(f'First record hash: {records[0].get(\"hash\", \"N/A\")[:16]}...')
print(f'Last record hash: {records[-1].get(\"hash\", \"N/A\")[:16]}...')
"

# 3. 篡改一条记录
sed -i 's/"success": true/"success": false/' /tmp/audit_original.log

# 4. 验证篡改被检测
python3 -c "
import json, hmac, hashlib
with open('/tmp/audit_original.log') as f:
    records = [json.loads(line) for line in f if line.strip()]

# 验证哈希链
prev_hash = '0' * 64
tampered = False
for i, record in enumerate(records):
    expected = hmac.new(
        b'secret_key',
        f'{prev_hash}{json.dumps(record, sort_keys=True)}'.encode(),
        hashlib.sha256
    ).hexdigest()
    if record.get('hash') != expected:
        print(f'TAMPERED at record {i}')
        tampered = True
        break
    prev_hash = record['hash']

if not tampered:
    print('HASH CHAIN VALID')
"
```

**预期结果**:
- 篡改审计日志后，HMAC 哈希链验证失败
- 能精确定位被篡改的记录位置
- 篡改检测工具能正常工作

**验证方法**:
- 检查审计日志是否每条记录都包含 HMAC 哈希
- 检查哈希链是否链式连接（每条记录包含前一条记录的哈希）

**严重级别**: P1

---

## 6. 资源隔离测试用例

### RES-001: 业务影响面验证（第十三条）

**测试目的**: 验证单实例故障的业务影响面 ≤ 5%

**测试步骤**:
```bash
# 1. 启动正常流量（模拟 1000 QPS）
python3 -c "
import requests, time, threading
def worker():
    while True:
        try:
            requests.post('http://localhost:8080/execute', json={'code': 'print(1)'}, timeout=1)
        except:
            pass
        time.sleep(0.001)
for _ in range(10):
    threading.Thread(target=worker, daemon=True).start()
time.sleep(30)
" &

# 2. 记录正常 QPS
NORMAL_QPS=$(curl -s http://localhost:9090/metrics | grep photon_requests_per_second | tail -1 | awk '{print $2}')
echo "Normal QPS: $NORMAL_QPS"

# 3. 杀掉一个 worker 实例
WORKER_PID=$(pgrep -f photon_worker | head -1)
kill -9 $WORKER_PID
echo "Killed worker: $WORKER_PID"

# 4. 记录受影响的请求数（10秒窗口）
sleep 10
AFFECTED=$(curl -s http://localhost:9090/metrics | grep photon_affected_requests | tail -1 | awk '{print $2}')
TOTAL=$(curl -s http://localhost:9090/metrics | grep photon_total_requests | tail -1 | awk '{print $2}')

# 5. 计算影响面
IMPACT_PERCENT=$(python3 -c "print(f'{$AFFECTED / $TOTAL * 100:.2f}')")
echo "Impact: $IMPACT_PERCENT%"

# 6. 验证 ≤ 5%
python3 -c "
impact = float('$IMPACT_PERCENT')
if impact <= 5.0:
    print(f'PASS: Impact {impact}% <= 5%')
else:
    print(f'FAIL: Impact {impact}% > 5%')
"
```

**预期结果**:
- 单实例故障的业务影响面 ≤ 5%
- 受影响请求能在 5 秒内自动恢复
- 业务影响面 metrics 能正常采集和展示

**验证方法**:
- 检查 BusinessImpactTracker 是否正确计算影响面
- 检查监控看板是否展示业务影响面指标
- 检查告警是否在影响面超过 5% 时触发

**严重级别**: P1

---

## 7. 测试用例执行记录表

| 编号 | 测试项 | 执行结果 | 发现问题 | 修复状态 | 复测结果 |
|------|--------|---------|---------|---------|---------|
| ESC-001 | Namespace 逃逸 | ⏳ 待执行 | - | - | - |
| ESC-002 | seccomp 绕过 | ⏳ 待执行 | - | - | - |
| ESC-003 | Landlock 绕过 | ⏳ 待执行 | - | - | - |
| ESC-004 | VM 逃逸 | ⏳ 待执行 | - | - | - |
| ESC-005 | 内核漏洞利用 | ⏳ 待执行 | - | - | - |
| PRI-001 | SUID 提权 | ⏳ 待执行 | - | - | - |
| PRI-002 | Capability 残留 | ⏳ 待执行 | - | - | - |
| PRI-003 | 解释器白名单绕过 | ⏳ 待执行 | - | - | - |
| LEAK-001 | /proc 信息泄露 | ⏳ 待执行 | - | - | - |
| LEAK-002 | 跨实例文件访问 | ⏳ 待执行 | - | - | - |
| LEAK-003 | HMAC 密钥泄露 | ⏳ 待执行 | - | - | - |
| NET-001 | 内网访问拦截 | ⏳ 待执行 | - | - | - |
| NET-002 | DNS 隧道绕过 | ⏳ 待执行 | - | - | - |
| AUD-001 | 审计日志防篡改 | ⏳ 待执行 | - | - | - |
| RES-001 | 业务影响面验证 | ⏳ 待执行 | - | - | - |

---

**文档状态**: 待第三方审计机构执行
**测试环境要求**: 裸机 + root + KVM + CAP_BPF + CRIU
**预计执行时间**: 5-7 人天
