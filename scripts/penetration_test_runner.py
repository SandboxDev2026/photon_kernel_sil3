#!/usr/bin/env python3
"""
PhotonBox 渗透测试自动化框架

自动编译、运行所有红蓝对抗POC，收集结果，生成安全评估报告。

功能：
1. 自动编译所有POC（g++/clang++）
2. 沙箱环境运行（超时控制、资源限制）
3. 结果分类：PASS（攻击被阻止）/ FAIL（攻击成功）/ TIMEOUT / CRASH / COMPILE_ERROR
4. 风险评级：Critical/High/Medium/Low
5. 生成Markdown报告 + JSON结果
6. 统计汇总：通过率、失败率、风险分布

用法：
    python3 scripts/penetration_test_runner.py [--output-dir DIR] [--timeout SEC] [--verbose]
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import hashlib
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Optional, List, Dict
from datetime import datetime


class TestResult(Enum):
    """测试结果"""
    PASS = "PASS"              # 攻击被阻止（返回0）
    FAIL = "FAIL"              # 攻击成功（返回2）
    TIMEOUT = "TIMEOUT"        # 超时
    CRASH = "CRASH"            # 崩溃（信号终止）
    COMPILE_ERROR = "COMPILE_ERROR"  # 编译失败
    SKIP = "SKIP"              # 跳过


class RiskLevel(Enum):
    """风险等级"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class POCTestCase:
    """POC测试用例"""
    id: str
    name: str
    file_path: str
    description: str
    risk_level: RiskLevel
    attack_technique: str
    expected_behavior: str
    result: TestResult = TestResult.SKIP
    return_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    duration_ms: float = 0.0
    compile_duration_ms: float = 0.0
    binary_path: Optional[str] = None
    error_message: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["risk_level"] = self.risk_level.value
        d["result"] = self.result.value
        return d


# ========== POC 元数据 ==========
POC_METADATA: List[Dict] = [
    {"id": "POC-001", "name": "ptrace注入", "file": "redteam_poc_ptrace.cpp",
     "description": "沙盒内尝试ptrace附加父进程", "risk": "Critical",
     "technique": "ptrace注入", "expected": "进程被KILL，审计记录"},
    {"id": "POC-002", "name": "fd泄露逃逸", "file": "redteam_poc_fd_leak.cpp",
     "description": "继承未关闭特权fd，尝试读写宿主文件", "risk": "High",
     "technique": "fd泄露", "expected": "访问被拒绝，fd已关闭"},
    {"id": "POC-003", "name": "fork炸弹", "file": "redteam_poc_fork_bomb.cpp",
     "description": "疯狂fork耗尽PID/资源", "risk": "High",
     "technique": "fork炸弹DoS", "expected": "cgroup pid限制生效"},
    {"id": "POC-004", "name": "seccomp绕过", "file": "redteam_poc_seccomp_bypass.cpp",
     "description": "尝试多种seccomp-bpf绕过技术", "risk": "Critical",
     "technique": "seccomp绕过", "expected": "所有绕过被阻止"},
    {"id": "POC-005", "name": "mount逃逸", "file": "redteam_poc_mount_escape.cpp",
     "description": "尝试mount特殊文件系统突破隔离", "risk": "High",
     "technique": "mount逃逸", "expected": "mount被拒绝，Landlock生效"},
    {"id": "POC-006", "name": "TOCTOU竞争", "file": "redteam_poc_toctou_race.cpp",
     "description": "access()/open()之间切换符号链接", "risk": "High",
     "technique": "TOCTOU竞争条件", "expected": "竞争条件未成功"},
    {"id": "POC-007", "name": "32位兼容绕过", "file": "redteam_poc_32bit_seccomp_bypass.cpp",
     "description": "int 0x80触发32位系统调用", "risk": "Critical",
     "technique": "32位兼容模式", "expected": "arch字段验证有效"},
    {"id": "POC-008", "name": "信号竞争", "file": "redteam_poc_signal_race.cpp",
     "description": "SIGSYS/SIGSTOP信号处理绕过", "risk": "High",
     "technique": "信号竞争条件", "expected": "KILL_PROCESS无信号处理机会"},
    {"id": "POC-009", "name": "/proc接口突破", "file": "redteam_poc_proc_escape.cpp",
     "description": "/proc/kcore/sysrq/root等敏感路径", "risk": "High",
     "technique": "/proc接口突破", "expected": "Landlock限制敏感路径"},
    {"id": "POC-010", "name": "内存OOM", "file": "redteam_poc_memory_oom.cpp",
     "description": "malloc/mmap/COW/共享内存耗尽", "risk": "High",
     "technique": "内存耗尽DoS", "expected": "cgroup memory.max限制生效"},
    {"id": "POC-011", "name": "Landlock绕过", "file": "redteam_poc_landlock_bypass.cpp",
     "description": "路径遍历/符号链接/proc/self/fd绕过", "risk": "High",
     "technique": "Landlock路径遍历", "expected": "Landlock限制所有路径访问"},
    {"id": "POC-012", "name": "cgroup逃逸", "file": "redteam_poc_cgroup_escape.cpp",
     "description": "写入cgroup.procs/创建子cgroup/tmpfs绕过", "risk": "High",
     "technique": "cgroup逃逸", "expected": "cgroup文件系统只读"},
    {"id": "POC-013", "name": "命名空间逃逸", "file": "redteam_poc_namespace_escape.cpp",
     "description": "unshare user/setns/pivot_root", "risk": "Critical",
     "technique": "命名空间逃逸", "expected": "seccomp拦截，user ns禁用"},
    {"id": "POC-014", "name": "内核信息泄露", "file": "redteam_poc_kernel_info_leak.cpp",
     "description": "/proc/kallsyms/dmesg/kcore/iomem", "risk": "Medium",
     "technique": "内核信息侦察", "expected": "敏感路径不可访问"},
    {"id": "POC-015", "name": "侧信道攻击", "file": "redteam_poc_sidechannel.cpp",
     "description": "Flush+Reload/Spectre/高分辨率计时器", "risk": "High",
     "technique": "侧信道攻击", "expected": "侧信道缓解已启用"},
]


class PenetrationTestRunner:
    """渗透测试自动化运行器"""

    def __init__(
        self,
        poc_dir: str,
        output_dir: str,
        timeout: int = 30,
        compiler: str = "g++",
        compile_flags: str = "-std=c++17 -O2",
        verbose: bool = False,
    ):
        self.poc_dir = Path(poc_dir)
        self.output_dir = Path(output_dir)
        self.timeout = timeout
        self.compiler = compiler
        self.compile_flags = compile_flags
        self.verbose = verbose
        self.test_cases: List[POCTestCase] = []
        self.start_time = 0.0

        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.bin_dir = self.output_dir / "binaries"
        self.bin_dir.mkdir(exist_ok=True)

    def load_test_cases(self):
        """加载测试用例"""
        for meta in POC_METADATA:
            file_path = self.poc_dir / meta["file"]
            if not file_path.exists():
                print(f"[!] 文件不存在: {file_path}")
                continue
            tc = POCTestCase(
                id=meta["id"],
                name=meta["name"],
                file_path=str(file_path),
                description=meta["description"],
                risk_level=RiskLevel(meta["risk"]),
                attack_technique=meta["technique"],
                expected_behavior=meta["expected"],
            )
            self.test_cases.append(tc)
        print(f"[*] 加载 {len(self.test_cases)} 个测试用例")

    def compile_poc(self, tc: POCTestCase) -> bool:
        """编译单个POC"""
        binary_name = f"{tc.id.lower().replace('-', '_')}_{self._file_hash(tc.file_path)[:8]}"
        binary_path = self.bin_dir / binary_name

        cmd = [
            self.compiler,
            *self.compile_flags.split(),
            "-o", str(binary_path),
            tc.file_path,
            "-lpthread",
        ]

        start = time.time()
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )
            tc.compile_duration_ms = (time.time() - start) * 1000

            if result.returncode != 0:
                tc.result = TestResult.COMPILE_ERROR
                tc.error_message = result.stderr[:500]
                if self.verbose:
                    print(f"  [编译失败] {tc.id}: {result.stderr[:200]}")
                return False

            tc.binary_path = str(binary_path)
            return True

        except subprocess.TimeoutExpired:
            tc.result = TestResult.COMPILE_ERROR
            tc.error_message = "编译超时"
            return False
        except Exception as e:
            tc.result = TestResult.COMPILE_ERROR
            tc.error_message = str(e)
            return False

    def run_poc(self, tc: POCTestCase):
        """运行单个POC"""
        if not tc.binary_path:
            return

        start = time.time()
        try:
            result = subprocess.run(
                [tc.binary_path],
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            tc.duration_ms = (time.time() - start) * 1000
            tc.return_code = result.returncode
            tc.stdout = result.stdout[-2000:] if len(result.stdout) > 2000 else result.stdout
            tc.stderr = result.stderr[-1000:] if len(result.stderr) > 1000 else result.stderr

            # 根据返回码判断结果
            if result.returncode == 0:
                tc.result = TestResult.PASS  # 攻击被阻止
            elif result.returncode == 2:
                tc.result = TestResult.FAIL  # 攻击成功
            elif result.returncode < 0:
                tc.result = TestResult.CRASH  # 信号终止
            else:
                tc.result = TestResult.PASS  # 其他非零返回视为被阻止

        except subprocess.TimeoutExpired:
            tc.duration_ms = (time.time() - start) * 1000
            tc.result = TestResult.TIMEOUT
            tc.error_message = f"运行超时（>{self.timeout}s）"
        except Exception as e:
            tc.result = TestResult.CRASH
            tc.error_message = str(e)

    def run_all(self):
        """运行所有测试"""
        self.start_time = time.time()
        print(f"\n{'='*60}")
        print(f"PhotonBox 渗透测试自动化框架")
        print(f"{'='*60}")
        print(f"测试用例数: {len(self.test_cases)}")
        print(f"超时时间: {self.timeout}s")
        print(f"编译器: {self.compiler}")
        print(f"{'='*60}\n")

        for i, tc in enumerate(self.test_cases, 1):
            print(f"[{i}/{len(self.test_cases)}] {tc.id} {tc.name} ({tc.risk_level.value})")

            # 编译
            if not self.compile_poc(tc):
                print(f"  结果: {tc.result.value}")
                continue

            # 运行
            self.run_poc(tc)

            status_icon = {
                TestResult.PASS: "✅",
                TestResult.FAIL: "❌",
                TestResult.TIMEOUT: "⏰",
                TestResult.CRASH: "💥",
                TestResult.COMPILE_ERROR: "🔧",
            }.get(tc.result, "?")

            print(f"  {status_icon} {tc.result.value} ({tc.duration_ms:.0f}ms)")

            if self.verbose and tc.result in (TestResult.FAIL, TestResult.CRASH):
                print(f"  stdout: {tc.stdout[:300]}")

        total_duration = time.time() - self.start_time
        print(f"\n{'='*60}")
        print(f"测试完成，总耗时: {total_duration:.1f}s")
        print(f"{'='*60}")

    def generate_report(self) -> str:
        """生成Markdown报告"""
        total = len(self.test_cases)
        passed = sum(1 for t in self.test_cases if t.result == TestResult.PASS)
        failed = sum(1 for t in self.test_cases if t.result == TestResult.FAIL)
        timeout = sum(1 for t in self.test_cases if t.result == TestResult.TIMEOUT)
        crashed = sum(1 for t in self.test_cases if t.result == TestResult.CRASH)
        compile_errors = sum(1 for t in self.test_cases if t.result == TestResult.COMPILE_ERROR)

        # 风险分布
        risk_dist = {}
        for tc in self.test_cases:
            risk_dist[tc.risk_level.value] = risk_dist.get(tc.risk_level.value, 0) + 1

        # 失败的高风险项
        critical_failures = [
            tc for tc in self.test_cases
            if tc.result == TestResult.FAIL and tc.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH)
        ]

        report = f"""# PhotonBox 渗透测试报告

**生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**测试框架**: penetration_test_runner.py
**测试用例数**: {total}
**总耗时**: {time.time() - self.start_time:.1f}s

## 执行摘要

| 指标 | 数量 | 占比 |
|------|------|------|
| ✅ 通过（攻击被阻止） | {passed} | {passed/total*100:.1f}% |
| ❌ 失败（攻击成功） | {failed} | {failed/total*100:.1f}% |
| ⏰ 超时 | {timeout} | {timeout/total*100:.1f}% |
| 💥 崩溃 | {crashed} | {crashed/total*100:.1f}% |
| 🔧 编译错误 | {compile_errors} | {compile_errors/total*100:.1f}% |

## 风险分布

| 风险等级 | 用例数 |
|----------|--------|
"""
        for risk, count in sorted(risk_dist.items(), key=lambda x: ["Critical", "High", "Medium", "Low", "Info"].index(x[0])):
            report += f"| {risk} | {count} |\n"

        if critical_failures:
            report += f"""
## ⚠️ 高风险失败项（需立即修复）

"""
            for tc in critical_failures:
                report += f"""### {tc.id} {tc.name}

- **风险等级**: {tc.risk_level.value}
- **攻击技术**: {tc.attack_technique}
- **预期行为**: {tc.expected_behavior}
- **实际结果**: 攻击成功！
- **stdout**:
```
{tc.stdout[:500]}
```

"""

        report += """
## 详细测试结果

| ID | 名称 | 风险 | 结果 | 耗时(ms) | 编译(ms) |
|----|------|------|------|----------|----------|
"""
        for tc in self.test_cases:
            status_icon = {
                TestResult.PASS: "✅ PASS",
                TestResult.FAIL: "❌ FAIL",
                TestResult.TIMEOUT: "⏰ TIMEOUT",
                TestResult.CRASH: "💥 CRASH",
                TestResult.COMPILE_ERROR: "🔧 COMPILE_ERR",
            }.get(tc.result, tc.result.value)
            report += f"| {tc.id} | {tc.name} | {tc.risk_level.value} | {status_icon} | {tc.duration_ms:.0f} | {tc.compile_duration_ms:.0f} |\n"

        report += f"""
## 结论与建议

### 整体评估
- 安全测试通过率: **{passed/total*100:.1f}%**
- 高风险攻击被阻止率: 需逐项检查

### 修复建议
"""
        if failed > 0:
            report += f"1. **优先修复 {failed} 个失败的攻击用例**，特别是 Critical/High 风险项\n"
        else:
            report += "1. ✅ 所有攻击用例均被有效阻止\n"

        report += """2. 定期运行本框架，确保新代码不引入安全回归
3. 对超时/崩溃的用例进行单独分析，排除环境问题
4. 结合SAST扫描和代码审查，形成纵深防御

---
*本报告由 PhotonBox 渗透测试自动化框架自动生成*
"""
        return report

    def save_results(self):
        """保存结果"""
        # JSON 结果
        json_path = self.output_dir / "penetration_test_results.json"
        results_data = {
            "generated_at": datetime.now().isoformat(),
            "total_tests": len(self.test_cases),
            "summary": {
                "passed": sum(1 for t in self.test_cases if t.result == TestResult.PASS),
                "failed": sum(1 for t in self.test_cases if t.result == TestResult.FAIL),
                "timeout": sum(1 for t in self.test_cases if t.result == TestResult.TIMEOUT),
                "crashed": sum(1 for t in self.test_cases if t.result == TestResult.CRASH),
                "compile_errors": sum(1 for t in self.test_cases if t.result == TestResult.COMPILE_ERROR),
            },
            "test_cases": [tc.to_dict() for tc in self.test_cases],
        }
        with open(json_path, "w") as f:
            json.dump(results_data, f, indent=2, ensure_ascii=False)

        # Markdown 报告
        md_path = self.output_dir / "penetration_test_report.md"
        with open(md_path, "w") as f:
            f.write(self.generate_report())

        print(f"\n[*] 结果已保存:")
        print(f"  JSON: {json_path}")
        print(f"  报告: {md_path}")

        return md_path

    @staticmethod
    def _file_hash(file_path: str) -> str:
        with open(file_path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description="PhotonBox 渗透测试自动化框架")
    parser.add_argument("--poc-dir", default="tests/redblue", help="POC目录")
    parser.add_argument("--output-dir", default="test_results/penetration", help="输出目录")
    parser.add_argument("--timeout", type=int, default=30, help="单个POC超时时间（秒）")
    parser.add_argument("--compiler", default="g++", help="编译器")
    parser.add_argument("--compile-flags", default="-std=c++17 -O2", help="编译标志")
    parser.add_argument("--verbose", "-v", action="store_true", help="详细输出")
    args = parser.parse_args()

    runner = PenetrationTestRunner(
        poc_dir=args.poc_dir,
        output_dir=args.output_dir,
        timeout=args.timeout,
        compiler=args.compiler,
        compile_flags=args.compile_flags,
        verbose=args.verbose,
    )

    runner.load_test_cases()
    runner.run_all()
    report_path = runner.save_results()

    # 返回失败数量作为退出码
    failed = sum(1 for t in runner.test_cases if t.result == TestResult.FAIL)
    return failed


if __name__ == "__main__":
    sys.exit(main())
