# 网络分层防御 —— Agent 沙盒场景

## 概述

内网隔离、网关隔离、网段隔离三者属于网络分层防御，从粗到细：

```
网段隔离（L3，最粗） → 网关隔离（边界代理） → 内网隔离（沙盒实例级，最细）
```

常和沙盒内部 eBPF/seccomp 网络策略叠加，形成多层网络边界。

**目标**：即使沙盒被逃逸，也不能横向扫描内网、访问内部服务、数据库、中间件。

## 三层防御架构

```
┌─────────────────────────────────────────────────────────────┐
│                    公网 Internet                             │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│  第一层：网段隔离（L3 网络层，VLAN/子网）                    │
│  沙盒池独立子网 10.0.99.0/24                               │
│  防火墙ACL：禁止访问业务网段 10.0.1.0/24                    │
│  仅允许出站外网白名单                                        │
└───────────────────────────┬─────────────────────────────────┘
                            │（强制经过网关，无直接路由）
┌───────────────────────────▼─────────────────────────────────┐
│  第二层：网关隔离（边界代理网关）                             │
│  所有沙盒流量强制经过隔离网关                                 │
│  - 域名/IP白黑名单                                           │
│  - 出站速率限流、连接数限制（防DoS）                          │
│  - DNS劫持与校验（防止DNS隧道、内网域名解析）                 │
│  - 网络访问审计日志（租户ID、CapabilityToken、HMAC哈希链）   │
│  - 审批模式（高危请求人工审批，对接Policy+Identity平面）      │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│  第三层：内网隔离（沙盒实例级）                               │
│  即使上层配置出错逃逸，沙盒内部直接禁止访问内网保留地址        │
│  - eBPF钩子：拦截connect，匹配内网IP直接拒绝（需CAP_BPF）    │
│  - seccomp-bpf：拦截connect，简单场景可用                     │
│  - 隔离网关层再次校验：双重防护                                │
│                                                               │
│  拦截地址集合：                                               │
│  - 10.0.0.0/8       (RFC1918 A类)                           │
│  - 172.16.0.0/12    (RFC1918 B类)                           │
│  - 192.168.0.0/16   (RFC1918 C类)                           │
│  - 127.0.0.0/8       (回环，防止访问宿主机本地服务)           │
│  - 169.254.0.0/16    (链路本地、云厂商元数据服务，高危)       │
│  - 0.0.0.0/8, 100.64.0.0/10, 192.0.0.0/24, ...            │
│  - 224.0.0.0/4 (组播), 240.0.0.0/4 (保留)                  │
└─────────────────────────────────────────────────────────────┘
```

## 各层详细说明

### 第一层：网段隔离（L3 网络层）

**粒度**：整个沙盒实例池处在独立子网

**实现方式**：
- K8s NetworkPolicy（`deploy/network-policies.yaml`）
- 物理防火墙 / 云安全组
- VLAN / 子网划分

**配置示例**：
```
业务网段：10.0.1.0/24 （API、数据库、Redis）
沙盒执行网段：10.0.99.0/24
防火墙ACL：
  10.0.99.0/24 禁止访问 10.0.1.0/24
  仅允许沙盒网段访问指定外网IP/域名白名单
```

**优点**：部署简单，K8s NetworkPolicy、物理防火墙、云安全组直接实现。

**缺点**：同一沙盒子网内部，沙盒实例之间默认互通；一个被攻陷可以扫描、攻击同网段其他沙盒。

**结论**：网段隔离是第一道防线，不能单独作为唯一防护。

### 第二层：网关隔离（边界代理网关）

**粒度**：所有沙盒流量强制经过代理网关，沙盒本身没有直接路由

**核心功能**（`isolation_gateway.hpp/cpp`）：
1. **域名/IP白黑名单**：支持通配符 `*.example.com`，端口级控制
2. **出站速率限流**：每沙盒最大并发连接、每秒新建连接、带宽限制、单连接最大字节数
3. **DNS劫持与校验**：强制DNS服务器，阻止自定义DNS，防止DNS隧道、内网域名解析
4. **网络访问审计日志**：每条连接记录租户ID、CapabilityToken票据、HMAC审计哈希链
5. **审批模式**：高危外部网络请求进入人工审批（对接 Policy+Identity 平面）

**两种实现形态**：
1. **Sidecar 模式**：每个沙盒Pod附带sidecar代理（istio/envoy），生成 envoy 配置
2. **集中式隔离网关**：沙盒子网唯一网关出口，生成 iptables/K8s NetworkPolicy

**关键点**：沙盒内部配置默认网关指向隔离网关；沙盒不能绕过网关直接发包。

**优点**：统一管控所有网络行为；网络策略不用每个沙盒单独配置；审计集中。

**缺点**：单点风险，网关需要高可用；带来少量网络延迟。

### 第三层：内网隔离（沙盒实例级）

**粒度**：单个沙盒实例层面，拦截内网保留地址访问

**核心实现**（`network_isolation.hpp/cpp`）：
- `InternalNetworkPolicy`：内网IP检测、eBPF/seccomp/iptables规则生成
- `DnsHijackManager`：DNS劫持、强制DNS服务器、resolv.conf生成

**三处落地**：
1. **eBPF钩子**：拦截 connect 系统调用，匹配内网IP直接拒绝（需 CAP_BPF）
   - 生成完整 eBPF C 代码（`generate_ebpf_filter()`）
2. **seccomp-bpf**：拦截 connect，简单场景可用，粒度弱于eBPF
   - 生成 seccomp 规则描述（`generate_seccomp_rules()`）
3. **隔离网关层再次校验**：双重防护（`IsolationGatewayConfig.enable_internal_network_block`）

**注意**：内网隔离≠禁止全部网络；只是禁止访问内网私有网段；外网白名单照常放行。

## 防御效果验证

**假设场景**：沙盒逃逸，拿到宿主机权限

| 防御层 | 作用 | 逃逸后效果 |
|--------|------|-----------|
| 网段ACL | 阻止访问业务数据库网段 | 无法访问 10.0.1.0/24 |
| 隔离网关 | 没有网关权限无法绕过出站管控 | 所有出站流量被审计/过滤 |
| 沙盒eBPF | 拦截直接connect内网IP | 兜底，即使网关配置错误也拦截 |

**结论**：多层失败安全，任意一层配置错误，剩下两层继续兜底。

## 和四层控制平面对应

| 网络防御层 | 对应控制平面 | 实现模块 |
|-----------|-------------|---------|
| 网段隔离 | Control Plane | TaskSpec.NetworkSpec + K8s NetworkPolicy |
| 网关隔离 | Policy + Identity | IsolationGateway + PolicyEngine + ApprovalManager |
| 内网隔离 | Execution Plane | InternalNetworkPolicy + eBPF/seccomp |
| 网络审计 | Evidence + Release | ConnectionRecord + HMAC审计哈希链 + EvidenceCollector |

## 不同后端的网络实现差异

| 运行时后端 | 网络隔离方式 | 内网拦截位置 |
|-----------|-------------|-------------|
| LightPool 进程沙盒 | net-namespace + eBPF | netns内iptables + eBPF connect钩子 |
| StrongPool Firecracker MicroVM | tap设备 + 隔离网关 | tap出口过滤 + VM内不感知内网 |
| Wasm沙盒 | WASI网络接口层 | 域名/IP过滤在WASI层，不需要内核eBPF |
| gVisor | 用户态网络栈 | gVisor内部网络过滤 + 外部网关 |

**注意**：netns隔离只是网络命名空间，本身不会拦截内网IP，必须自己加eBPF/seccomp规则。

## 常见踩坑点与防护

| 踩坑点 | 风险 | 防护措施 |
|--------|------|---------|
| 只做网段隔离，没有网关+实例级内网隔离 | 沙盒逃逸拿到同网段，可以横向扫描 | 三层叠加，不能只靠一层 |
| 只在网关做网络策略，沙盒内部没有拦截 | 网关配置错误时直接泄露内网 | 沙盒实例级eBPF/seccomp兜底 |
| 忽略云元数据地址 169.254.169.254 | Agent沙盒重大高危点，可窃取云凭证 | 169.254.0.0/16 整体拦截，标记为metadata高危 |
| DNS绕过：沙盒自定义DNS服务器绕开网关域名过滤 | 内网域名解析、DNS隧道数据外泄 | DNS劫持，强制DNS服务器，阻止自定义DNS |
| 沙盒之间直接通信 | 横向移动，一个被攻陷攻击其他沙盒 | K8s NetworkPolicy禁止沙盒Pod之间互通 |
| 回环地址 127.0.0.1 访问宿主机本地服务 | 访问宿主机上运行的未认证服务 | 127.0.0.0/8 拦截（除lo接口） |

## 快速部署

### 1. 应用 K8s NetworkPolicy（第一层）
```bash
kubectl apply -f deploy/network-policies.yaml
```

### 2. 部署隔离网关（第二层）
```bash
# 集中式网关模式
# 配置沙盒默认网关指向隔离网关
# 网关启用：域名白名单 + 限流 + DNS劫持 + 审计
```

### 3. 启用沙盒实例内网隔离（第三层）
```cpp
// C++ 代码中启用
photon_kernel::sandbox::InternalNetworkPolicy policy;
policy.enable();  // 默认启用

// 生成 eBPF 过滤器（需CAP_BPF加载）
std::string ebpf_code = policy.generate_ebpf_filter();

// 或生成 iptables 规则（在netns内执行）
auto rules = policy.generate_iptables_rules();
```

### 4. DNS 劫持
```cpp
photon_kernel::sandbox::DnsHijackConfig dns_config;
dns_config.forced_dns_server = "10.0.99.1";  // 隔离网关DNS
dns_config.block_custom_dns = true;
photon_kernel::sandbox::DnsHijackManager dns_mgr(dns_config);
// 生成 resolv.conf 写入沙盒
std::string resolv = dns_mgr.generate_resolv_conf();
```

## 测试覆盖

网络分层防御共 22 个单元测试：
- InternalNetworkPolicy: 11（RFC1918/回环/元数据/保留地址/公网允许/白名单覆盖/黑名单/eBPF生成/iptables生成/禁用启用）
- DnsHijackManager: 2（自定义DNS拦截/resolv.conf生成）
- IsolationGateway: 9（内网拦截/元数据拦截/公网允许/域名黑名单/限流/审计日志/K8s策略生成/envoy配置生成/DNS查询拦截）

全量测试：164 通过 + 2 跳过（CRIU）
