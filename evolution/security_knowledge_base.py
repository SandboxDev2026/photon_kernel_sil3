"""
PhotonBox 安全知识库系统

统一向量知识库架构（可抄点13）：
- 所有RAG功能共用一套知识库基础设施
- 支持多个命名空间：CVE漏洞库、防御规则库、攻击模式库、安全策略库等
- 轻量级TF-IDF检索（可替换为Milvus/Qdrant）

CVE漏洞知识库（可抄点1）：
- CVE数据结构化：CVE-ID、CVSS评分、影响版本、漏洞类型、PoC代码片段
- 逃逸技术专库：容器逃逸、VM逃逸、seccomp绕过、eBPF逃逸
- RAG检索增强生成：红方Agent生成攻击用例前检索相关CVE/逃逸技术
"""

import json
import math
import re
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# ============================================================
# 统一向量知识库基类（轻量级TF-IDF实现）
# ============================================================

@dataclass
class KnowledgeEntry:
    """知识库条目"""
    entry_id: str
    content: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    embedding: Optional[List[float]] = None
    created_at: float = field(default_factory=time.time)


class KnowledgeBase:
    """
    统一知识库基类

    轻量级TF-IDF检索实现，接口兼容Milvus/Qdrant等向量数据库。
    生产环境可替换为真实向量数据库，只需实现search()方法。
    """

    def __init__(self, name: str, max_entries: int = 10000):
        self.name = name
        self.max_entries = max_entries
        self._entries: Dict[str, KnowledgeEntry] = {}
        self._idf: Dict[str, float] = {}
        self._doc_freq: Counter = Counter()
        self._dirty = True

    def add(self, entry_id: str, content: str, metadata: Optional[Dict] = None) -> str:
        """添加知识库条目"""
        if len(self._entries) >= self.max_entries:
            self._evict_oldest()
        entry = KnowledgeEntry(
            entry_id=entry_id, content=content,
            metadata=metadata or {},
        )
        self._entries[entry_id] = entry
        self._doc_freq.update(set(self._tokenize(content)))
        self._dirty = True
        return entry_id

    def add_batch(self, entries: List[Tuple[str, str, Optional[Dict]]]) -> int:
        """批量添加"""
        count = 0
        for entry_id, content, metadata in entries:
            self.add(entry_id, content, metadata)
            count += 1
        return count

    def search(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """
        TF-IDF检索

        Args:
            query: 查询文本
            top_k: 返回前K条

        Returns:
            排序后的结果列表，每条包含entry_id、content、metadata、score
        """
        if self._dirty:
            self._compute_idf()
        query_tokens = self._tokenize(query)
        if not query_tokens:
            return []
        query_tf = Counter(query_tokens)
        scores = []
        for entry_id, entry in self._entries.items():
            doc_tokens = self._tokenize(entry.content)
            doc_tf = Counter(doc_tokens)
            score = self._cosine_similarity(query_tf, doc_tf)
            if score > 0:
                scores.append({
                    "entry_id": entry_id,
                    "content": entry.content,
                    "metadata": entry.metadata,
                    "score": round(score, 4),
                })
        scores.sort(key=lambda x: x["score"], reverse=True)
        return scores[:top_k]

    def get(self, entry_id: str) -> Optional[KnowledgeEntry]:
        """获取条目"""
        return self._entries.get(entry_id)

    def delete(self, entry_id: str) -> bool:
        """删除条目"""
        if entry_id in self._entries:
            del self._entries[entry_id]
            self._dirty = True
            return True
        return False

    def size(self) -> int:
        """条目数量"""
        return len(self._entries)

    def export(self, filepath: str) -> None:
        """导出知识库到JSON"""
        data = {
            "name": self.name,
            "entries": [
                {"entry_id": e.entry_id, "content": e.content, "metadata": e.metadata}
                for e in self._entries.values()
            ],
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def load(self, filepath: str) -> int:
        """从JSON加载知识库"""
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        count = 0
        for entry_data in data.get("entries", []):
            self.add(
                entry_data["entry_id"],
                entry_data["content"],
                entry_data.get("metadata"),
            )
            count += 1
        return count

    def _tokenize(self, text: str) -> List[str]:
        """简单分词（小写+非字母数字分割）"""
        return re.findall(r'[a-z0-9_]+', text.lower())

    def _compute_idf(self) -> None:
        """计算IDF"""
        n_docs = len(self._entries)
        if n_docs == 0:
            return
        self._idf = {
            term: math.log((n_docs + 1) / (freq + 1)) + 1
            for term, freq in self._doc_freq.items()
        }
        self._dirty = False

    def _cosine_similarity(self, tf1: Counter, tf2: Counter) -> float:
        """余弦相似度（使用TF-IDF权重）"""
        common = set(tf1.keys()) & set(tf2.keys())
        if not common:
            return 0.0
        dot = sum(tf1[t] * tf2[t] * self._idf.get(t, 1.0) ** 2 for t in common)
        norm1 = math.sqrt(sum((tf1[t] * self._idf.get(t, 1.0)) ** 2 for t in tf1))
        norm2 = math.sqrt(sum((tf2[t] * self._idf.get(t, 1.0)) ** 2 for t in tf2))
        if norm1 == 0 or norm2 == 0:
            return 0.0
        return dot / (norm1 * norm2)

    def _evict_oldest(self) -> None:
        """淘汰最旧条目"""
        if self._entries:
            oldest = min(self._entries.values(), key=lambda e: e.created_at)
            del self._entries[oldest.entry_id]
            self._dirty = True


# ============================================================
# CVE漏洞知识库（可抄点1）
# ============================================================

@dataclass
class CVERecord:
    """CVE记录结构化数据"""
    cve_id: str
    cvss_score: float
    cvss_severity: str  # critical/high/medium/low
    vulnerability_type: str  # RCE/提权/逃逸/信息泄露/DoS
    affected_versions: str
    exploit_conditions: str
    poc_code: str
    exploit_steps: List[str]
    detection_signatures: List[str]
    description: str
    published_date: str = ""
    references: List[str] = field(default_factory=list)


class CVEKnowledgeBase:
    """
    CVE漏洞知识库

    架构：CVE知识库 → RAG检索 → 攻击用例生成器 → 红方Agent
    - CVE数据结构化
    - 逃逸技术专库
    - RAG检索增强生成
    """

    def __init__(self):
        self._cve_kb = KnowledgeBase(name="cve_vulnerabilities")
        self._evasion_kb = KnowledgeBase(name="evasion_techniques")
        self._cve_records: Dict[str, CVERecord] = {}
        self._init_builtin_cves()
        self._init_evasion_techniques()

    def add_cve(self, record: CVERecord) -> str:
        """添加CVE记录"""
        self._cve_records[record.cve_id] = record
        content = self._cve_to_text(record)
        self._cve_kb.add(record.cve_id, content, {
            "cve_id": record.cve_id,
            "cvss_score": record.cvss_score,
            "cvss_severity": record.cvss_severity,
            "vulnerability_type": record.vulnerability_type,
        })
        return record.cve_id

    def search_cves(self, query: str, top_k: int = 5,
                     min_cvss: float = 0.0,
                     vuln_type: Optional[str] = None) -> List[Dict]:
        """
        检索相关CVE

        Args:
            query: 查询文本（如"container escape vulnerability"）
            top_k: 返回前K条
            min_cvss: 最低CVSS评分过滤
            vuln_type: 漏洞类型过滤

        Returns:
            CVE记录列表（含检索分数）
        """
        results = self._cve_kb.search(query, top_k=top_k * 2)
        filtered = []
        for r in results:
            meta = r["metadata"]
            if meta.get("cvss_score", 0) < min_cvss:
                continue
            if vuln_type and meta.get("vulnerability_type") != vuln_type:
                continue
            cve_id = meta["cve_id"]
            record = self._cve_records.get(cve_id)
            if record:
                filtered.append({
                    "cve_id": cve_id,
                    "cvss_score": record.cvss_score,
                    "cvss_severity": record.cvss_severity,
                    "vulnerability_type": record.vulnerability_type,
                    "description": record.description,
                    "poc_code": record.poc_code,
                    "exploit_steps": record.exploit_steps,
                    "detection_signatures": record.detection_signatures,
                    "search_score": r["score"],
                })
        return filtered[:top_k]

    def search_evasion_techniques(self, sandbox_type: str,
                                   top_k: int = 5) -> List[Dict]:
        """
        检索逃逸技术

        Args:
            sandbox_type: 沙盒类型（container/vm/seccomp/ebpf）
            top_k: 返回前K条

        Returns:
            逃逸技术列表
        """
        # 多query检索:英文+中文+技术关键词
        queries = [
            f"{sandbox_type} escape",
            f"{sandbox_type} sandbox",
            self._sandbox_type_to_chinese(sandbox_type),
        ]
        results = []
        seen_ids = set()
        for q in queries:
            for r in self._evasion_kb.search(q, top_k=top_k):
                if r["entry_id"] not in seen_ids:
                    results.append(r)
                    seen_ids.add(r["entry_id"])
        results.sort(key=lambda x: x["score"], reverse=True)
        return results[:top_k]

    def _sandbox_type_to_chinese(self, sandbox_type: str) -> str:
        """沙盒类型转中文关键词"""
        mapping = {
            "container": "容器逃逸 命名空间 cgroup",
            "vm": "虚拟机逃逸 virtio VMExit KVM",
            "seccomp": "系统调用过滤 绕过 syscall",
            "ebpf": "eBPF verifier map 越界",
        }
        return mapping.get(sandbox_type, sandbox_type)

    def generate_attack_case_context(self, target_sandbox_type: str) -> Dict:
        """
        为红方Agent生成攻击用例提供RAG上下文

        不是凭空生成，而是"基于真实漏洞的变异生成"。

        Args:
            target_sandbox_type: 目标沙盒类型

        Returns:
            包含相关CVE和逃逸技术的上下文
        """
        relevant_cves = self.search_cves(
            query=f"{target_sandbox_type} escape vulnerability",
            top_k=5, min_cvss=7.0,
        )
        evasion_techniques = self.search_evasion_techniques(
            target_sandbox_type, top_k=5,
        )
        return {
            "target_sandbox_type": target_sandbox_type,
            "relevant_cves": relevant_cves,
            "evasion_techniques": evasion_techniques,
            "attack_generation_prompt": self._build_attack_prompt(
                target_sandbox_type, relevant_cves, evasion_techniques,
            ),
        }

    def get_cve(self, cve_id: str) -> Optional[CVERecord]:
        """获取CVE记录"""
        return self._cve_records.get(cve_id)

    def stats(self) -> Dict:
        """知识库统计"""
        severity_counts = Counter(r.cvss_severity for r in self._cve_records.values())
        type_counts = Counter(r.vulnerability_type for r in self._cve_records.values())
        return {
            "total_cves": len(self._cve_records),
            "by_severity": dict(severity_counts),
            "by_type": dict(type_counts),
            "evasion_techniques": self._evasion_kb.size(),
        }

    def _cve_to_text(self, record: CVERecord) -> str:
        """CVE记录转文本（用于检索）"""
        return (
            f"{record.cve_id} {record.description} "
            f"vulnerability type: {record.vulnerability_type} "
            f"affected versions: {record.affected_versions} "
            f"exploit conditions: {record.exploit_conditions} "
            f"detection: {' '.join(record.detection_signatures)}"
        )

    def _build_attack_prompt(self, sandbox_type: str,
                              cves: List[Dict],
                              techniques: List[Dict]) -> str:
        """构建攻击用例生成Prompt"""
        cve_summary = "\n".join(
            f"- {c['cve_id']} (CVSS {c['cvss_score']}): {c['description']}"
            for c in cves[:3]
        )
        tech_summary = "\n".join(
            f"- {t['metadata'].get('technique_name', t['entry_id'])}: {t['content'][:100]}"
            for t in techniques[:3]
        )
        return (
            f"基于以下真实漏洞和逃逸技术，为{sandbox_type}沙盒生成攻击用例：\n\n"
            f"相关CVE：\n{cve_summary}\n\n"
            f"逃逸技术：\n{tech_summary}\n\n"
            f"要求：\n"
            f"1. 基于真实PoC变异，不要凭空生成\n"
            f"2. 包含攻击步骤、预期结果、检测特征\n"
            f"3. 标注攻击成功率估计和风险等级"
        )

    def _init_builtin_cves(self) -> None:
        """初始化内置CVE记录（沙盒逃逸相关）"""
        builtin_cves = [
            CVERecord(
                cve_id="CVE-2022-0185",
                cvss_score=8.4,
                cvss_severity="high",
                vulnerability_type="提权",
                affected_versions="Linux kernel 5.1-5.16",
                exploit_conditions="需要CAP_SYS_ADMIN或用户命名空间",
                poc_code="""# fsconfig() 堆溢出提权
# 利用 fsconfig 系统调用中的整数溢出
import subprocess
# 触发堆溢出覆盖cred结构体
subprocess.run(['unshare', '-U', '-m', 'sh', '-c', '''
mount -t tmpfs none /tmp
# fsconfig 溢出利用...
'''])""",
                exploit_steps=[
                    "创建用户命名空间获取CAP_SYS_ADMIN",
                    "调用fsconfig()触发整数溢出",
                    "堆溢出覆盖task_struct->cred",
                    "提权至root",
                ],
                detection_signatures=[
                    "fsconfig系统调用异常参数",
                    "用户命名空间内mount操作",
                    "cred结构体内存异常",
                ],
                description="Linux内核fsconfig()整数溢出导致的堆溢出提权漏洞",
                published_date="2022-01-18",
            ),
            CVERecord(
                cve_id="CVE-2021-4034",
                cvss_score=7.8,
                cvss_severity="high",
                vulnerability_type="提权",
                affected_versions="polkit <= 0.120",
                exploit_conditions="本地用户访问",
                poc_code="""# PwnKit pkexec 提权
# 利用 pkexec 处理命令行参数时的越界写入
import os, ctypes
# 构造恶意环境变量触发out-of-bounds写
env = ['GCONV_PATH=./pwnkit', 'PATH=GCONV_PATH=.', 'CHARSET=PWNKIT']
os.execve('/usr/bin/pkexec', ['pkexec'], env)""",
                exploit_steps=[
                    "构造恶意GCONV_PATH环境变量",
                    "调用pkexec触发argv[0]越界写入",
                    "覆盖环境变量为GCONV_PATH",
                    "加载恶意共享库提权",
                ],
                detection_signatures=[
                    "pkexec进程异常环境变量",
                    "GCONV_PATH包含相对路径",
                    "非root用户加载自定义.so",
                ],
                description="polkit pkexec本地提权漏洞（PwnKit）",
                published_date="2022-01-25",
            ),
            CVERecord(
                cve_id="CVE-2023-32233",
                cvss_score=7.8,
                cvss_severity="high",
                vulnerability_type="提权",
                affected_versions="Linux kernel <= 6.3.1",
                exploit_conditions="需要CAP_NET_ADMIN或用户命名空间",
                poc_code="""# nf_tables Use-After-Free 提权
# 利用 nf_tables 处理 batch 请求时的 UAF
import socket
# 创建 netlink socket 发送恶意 nf_tables 消息
# 触发 use-after-free 覆盖内核对象""",
                exploit_steps=[
                    "创建netlink socket",
                    "发送恶意nf_tables batch消息",
                    "触发匿名集合的use-after-free",
                    "覆盖内核对象提权",
                ],
                detection_signatures=[
                    "nf_tables系统调用异常",
                    "netlink消息包含恶意集合操作",
                    "内核内存UAF特征",
                ],
                description="Linux内核nf_tables use-after-free提权漏洞",
                published_date="2023-05-08",
            ),
            CVERecord(
                cve_id="CVE-2024-1086",
                cvss_score=7.8,
                cvss_severity="high",
                vulnerability_type="提权",
                affected_versions="Linux kernel 5.14-6.6",
                exploit_conditions="需要网络命名空间访问",
                poc_code="""# netfilter nf_tables 双重释放提权
# 利用 nft_verdict_init 中的双重释放
# 通过用户命名空间+网络命名空间触发""",
                exploit_steps=[
                    "创建用户+网络命名空间",
                    "配置恶意nf_tables规则",
                    "触发verdict对象双重释放",
                    "堆喷射覆盖cred提权",
                ],
                detection_signatures=[
                    "nf_tables verdict对象异常",
                    "命名空间内netfilter操作",
                    "内核堆双重释放特征",
                ],
                description="Linux内核netfilter nf_tables双重释放提权漏洞",
                published_date="2024-01-31",
            ),
            CVERecord(
                cve_id="CVE-2023-2640",
                cvss_score=7.8,
                cvss_severity="high",
                vulnerability_type="提权",
                affected_versions="Ubuntu kernel 5.4/5.15/6.2",
                exploit_conditions="本地用户，OverlayFS",
                poc_code="""# Ubuntu OverlayFS 提权
# 利用 Ubuntu 内核中 OverlayFS 的 setxattr 漏洞
# 设置 trusted.overlay.metacopy xattr 绕过权限检查""",
                exploit_steps=[
                    "创建OverlayFS挂载",
                    "设置恶意trusted.overlay.* xattr",
                    "绕过权限检查修改文件",
                    "提权至root",
                ],
                detection_signatures=[
                    "OverlayFS trusted xattr异常设置",
                    "非特权用户修改trusted属性",
                    "Ubuntu特有内核路径",
                ],
                description="Ubuntu内核OverlayFS本地提权漏洞",
                published_date="2023-07-26",
            ),
            CVERecord(
                cve_id="CVE-2021-22555",
                cvss_score=7.8,
                cvss_severity="high",
                vulnerability_type="提权",
                affected_versions="Linux kernel <= 5.12",
                exploit_conditions="需要netfilter访问",
                poc_code="""# netfilter x_tables 堆溢出提权
# 利用 xt_compat_target_from_user 中的堆溢出
# 通过 IPT_SO_SET_REPLACE 发送恶意规则""",
                exploit_steps=[
                    "创建netfilter socket",
                    "发送恶意IPT_SO_SET_REPLACE消息",
                    "触发compat_target堆溢出",
                    "覆盖内核对象提权",
                ],
                detection_signatures=[
                    "IPT_SO_SET_REPLACE异常大小",
                    "netfilter compat路径访问",
                    "内核堆溢出特征",
                ],
                description="Linux内核netfilter x_tables堆溢出提权漏洞",
                published_date="2021-07-07",
            ),
        ]
        for cve in builtin_cves:
            self.add_cve(cve)

    def _init_evasion_techniques(self) -> None:
        """初始化逃逸技术专库"""
        techniques = [
            ("container_cgroup_release_agent", "容器逃逸",
             "通过cgroup v1 release_agent逃逸容器。挂载cgroup文件系统，修改release_agent指向恶意脚本，触发cgroup删除执行命令。需要CAP_SYS_ADMIN。",
             {"technique_name": "cgroup release_agent逃逸", "sandbox_type": "container",
              "requires": ["CAP_SYS_ADMIN", "cgroup v1"], "risk": "high"}),
            ("container_procfs_escape", "容器逃逸",
             "通过/proc文件系统逃逸。利用/proc/1/root或/proc/sys/kernel/core_pattern访问宿主机文件系统。需要特定挂载配置。",
             {"technique_name": "procfs逃逸", "sandbox_type": "container",
              "requires": ["/proc挂载可写", "core_pattern可修改"], "risk": "high"}),
            ("container_mount_namespace_escape", "容器逃逸",
             "通过mount命名空间逃逸。利用CAP_SYS_ADMIN挂载宿主机磁盘到容器内，然后chroot访问宿主机文件系统。",
             {"technique_name": "mount命名空间逃逸", "sandbox_type": "container",
              "requires": ["CAP_SYS_ADMIN", "可访问宿主机块设备"], "risk": "critical"}),
            ("vm_virtio_escape", "VM逃逸",
             "通过virtio设备驱动漏洞逃逸虚拟机。攻击virtio-net/virtio-blk/virtio-vsock设备模拟中的内存安全漏洞，从Guest代码执行到宿主机。",
             {"technique_name": "virtio设备逃逸", "sandbox_type": "vm",
              "requires": ["virtio设备漏洞", "Guest内核访问"], "risk": "critical"}),
            ("vm_vmexit_escape", "VM逃逸",
             "通过VMExit处理漏洞逃逸。攻击VMM（如Firecracker/QEMU）在处理VMExit时的逻辑漏洞，构造特殊CPU状态触发越界访问或类型混淆。",
             {"technique_name": "VMExit处理逃逸", "sandbox_type": "vm",
              "requires": ["VMM VMExit处理漏洞", "Guest ring0访问"], "risk": "critical"}),
            ("seccomp_syscall_confusion", "seccomp绕过",
             "通过系统调用混淆绕过seccomp。利用x32 ABI、syscall号偏移、架构特定syscall（如ptrace、userfaultfd）绕过白名单过滤。",
             {"technique_name": "syscall混淆绕过", "sandbox_type": "seccomp",
              "requires": ["seccomp白名单不完整", "x32/多架构支持"], "risk": "high"}),
            ("seccomp_argument_injection", "seccomp绕过",
             "通过参数注入绕过seccomp。seccomp只过滤syscall号不过滤参数，利用允许的syscall（如openat、connect）传入恶意参数访问敏感资源。",
             {"technique_name": "参数注入绕过", "sandbox_type": "seccomp",
              "requires": ["seccomp仅过滤syscall号", "允许的syscall可滥用"], "risk": "medium"}),
            ("ebpf_verifier_bypass", "eBPF逃逸",
             "通过eBPF verifier漏洞逃逸。构造特殊eBPF程序利用verifier中的整数溢出、类型混淆、分支预测错误，绕过安全检查执行任意内核代码。",
             {"technique_name": "eBPF verifier绕过", "sandbox_type": "ebpf",
              "requires": ["CAP_BPF", "eBPF verifier漏洞"], "risk": "critical"}),
            ("ebpf_map_oob", "eBPF逃逸",
             "通过eBPF map越界读写逃逸。利用eBPF map操作中的边界检查漏洞，越界读写内核内存，泄露内核地址或覆盖内核对象。",
             {"technique_name": "eBPF map越界", "sandbox_type": "ebpf",
              "requires": ["CAP_BPF", "eBPF map操作漏洞"], "risk": "high"}),
            ("namespace_pivot_root_escape", "容器逃逸",
             "通过pivot_root/chroot逃逸。利用挂载命名空间中的pivot_root操作，将根文件系统切换到宿主机目录，绕过chroot限制。",
             {"technique_name": "pivot_root逃逸", "sandbox_type": "container",
              "requires": ["CAP_SYS_ADMIN", "mount命名空间"], "risk": "high"}),
            ("user_namespace_cap_escalation", "提权",
             "通过用户命名空间能力提升。在用户命名空间内获得CAP_SYS_ADMIN，然后利用内核漏洞（如CVE-2022-0185）从命名空间内提权到宿主机root。",
             {"technique_name": "用户命名空间提权", "sandbox_type": "container",
              "requires": ["用户命名空间可创建", "内核提权漏洞"], "risk": "critical"}),
            ("docker_socket_mount", "容器逃逸",
             "通过挂载Docker socket逃逸。容器内挂载/var/run/docker.sock，通过Docker API创建特权容器挂载宿主机根目录，执行任意命令。",
             {"technique_name": "Docker socket逃逸", "sandbox_type": "container",
              "requires": ["Docker socket挂载", "Docker API访问"], "risk": "critical"}),
        ]
        for tech_id, tech_type, content, metadata in techniques:
            metadata["technique_type"] = tech_type
            self._evasion_kb.add(tech_id, content, metadata)
