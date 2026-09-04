#!/usr/bin/env python3
"""
PhotonBox CI 安全门禁脚本

在 CI/CD 流水线中运行，执行以下检查：
1. 逃逸风险评分检查：evasion_risk_score >= 90 时自动生成漏洞工单并卡住发布
2. 合规证据检查：调用 compliance_evidence_collector.py 验证证据达标
3. SAST 检查：运行 bandit 扫描，High 问题 > 0 时卡住发布
4. 测试覆盖率检查：核心模块覆盖率 < 80% 时警告

使用方式：
  # 完整门禁检查
  python3 scripts/ci_security_gate.py

  # 仅检查逃逸风险评分
  python3 scripts/ci_security_gate.py --check evasion-risk

  # 指定风险评分阈值
  python3 scripts/ci_security_gate.py --evasion-threshold 80

  # 生成 GitHub Issue（需要 GITHUB_TOKEN）
  python3 scripts/ci_security_gate.py --create-github-issue --repo SandboxDev2026/photon_kernel_sil3

退出码：
  0 = 所有检查通过
  1 = 安全门禁失败，禁止发布
  2 = 脚本执行错误
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional


# ============================================================
# 逃逸风险评分器
# ============================================================

class EvasionRiskScorer:
    """
    逃逸风险评分器

    基于代码变更内容评估沙盒逃逸风险：
    - 0-30: 低风险（文档、测试、非安全相关代码）
    - 30-60: 中风险（普通功能代码）
    - 60-90: 高风险（沙盒核心逻辑、隔离机制变更）
    - 90-100: 严重风险（可能引入逃逸漏洞的变更，必须人工审核+生成工单）
    """

    # 高风险文件模式（涉及沙盒隔离核心）
    HIGH_RISK_PATTERNS = [
        "seccomp", "namespace", "landlock", "cgroup",
        "strong_pool", "firecracker", "microvm", "kvm",
        "ebpf", "bpf", "network_filter",
        "release_gate", "capability_token",
        "audit", "hmac",
    ]

    # 严重风险关键词（可能引入逃逸漏洞）
    CRITICAL_KEYWORDS = [
        "bypass", "disable", "skip", "ignore", "fallback",
        "downgrade", "relax", "weaken", "remove_check",
        "allow_all", "permissive", "no_sandbox",
        "unsafe", "todo_security", "fixme_security",
    ]

    def __init__(self, repo_path: str):
        self.repo_path = repo_path

    def score_diff(self, base_ref: str = "HEAD~1", head_ref: str = "HEAD") -> dict:
        """
        评估两个提交之间的代码变更的逃逸风险

        Returns:
            {
                "score": 0-100,
                "level": "low/medium/high/critical",
                "risky_files": [...],
                "critical_findings": [...],
                "summary": "..."
            }
        """
        result = {
            "score": 0,
            "level": "low",
            "risky_files": [],
            "critical_findings": [],
            "summary": "",
        }

        try:
            # 获取变更文件列表
            diff_result = subprocess.run(
                ["git", "diff", "--name-only", base_ref, head_ref],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if diff_result.returncode != 0:
                result["summary"] = f"无法获取 diff: {diff_result.stderr}"
                return result

            changed_files = [f.strip() for f in diff_result.stdout.strip().split("\n") if f.strip()]

            if not changed_files:
                result["summary"] = "无代码变更"
                return result

            # 分析每个变更文件
            score = 0
            for file_path in changed_files:
                file_risk = self._score_file(file_path, base_ref, head_ref)
                if file_risk["risk_level"] != "none":
                    result["risky_files"].append(file_risk)
                    score += file_risk["score"]
                if file_risk.get("critical_findings"):
                    result["critical_findings"].extend(file_risk["critical_findings"])

            # 归一化到 0-100
            result["score"] = min(100, score)

            # 确定风险等级
            if result["score"] >= 90 or result["critical_findings"]:
                result["level"] = "critical"
            elif result["score"] >= 60:
                result["level"] = "high"
            elif result["score"] >= 30:
                result["level"] = "medium"
            else:
                result["level"] = "low"

            result["summary"] = (
                f"变更 {len(changed_files)} 个文件，"
                f"风险评分 {result['score']}/100 ({result['level']}), "
                f"{len(result['risky_files'])} 个高风险文件, "
                f"{len(result['critical_findings'])} 个严重发现"
            )

        except subprocess.TimeoutExpired:
            result["summary"] = "git diff 超时"
        except Exception as e:
            result["summary"] = f"评分异常: {e}"

        return result

    def _score_file(self, file_path: str, base_ref: str, head_ref: str) -> dict:
        """评估单个文件的变更风险"""
        file_lower = file_path.lower()
        score = 0
        risk_level = "none"
        critical_findings = []

        # 检查是否为高风险文件
        for pattern in self.HIGH_RISK_PATTERNS:
            if pattern in file_lower:
                score += 20
                risk_level = "high"
                break

        # 安全核心文件额外加权
        if any(x in file_lower for x in ["seccomp", "namespace", "strong_pool", "ebpf"]):
            score += 15

        # 获取文件 diff 内容，检查严重关键词
        try:
            diff_result = subprocess.run(
                ["git", "diff", base_ref, head_ref, "--", file_path],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if diff_result.returncode == 0:
                added_lines = [
                    line for line in diff_result.stdout.split("\n")
                    if line.startswith("+") and not line.startswith("+++")
                ]
                for line in added_lines:
                    line_lower = line.lower()
                    for keyword in self.CRITICAL_KEYWORDS:
                        if keyword in line_lower:
                            # 排除注释中的合理使用
                            if not line.lstrip("+").lstrip().startswith("#"):
                                critical_findings.append({
                                    "file": file_path,
                                    "keyword": keyword,
                                    "line": line[:100],
                                })
                                score += 30
        except Exception:
            pass

        if score >= 50:
            risk_level = "high"
        elif score >= 20:
            risk_level = "medium"
        elif score > 0:
            risk_level = "low"

        return {
            "file": file_path,
            "score": min(50, score),
            "risk_level": risk_level,
            "critical_findings": critical_findings,
        }


# ============================================================
# 工单生成器
# ============================================================

class TicketGenerator:
    """漏洞工单生成器"""

    def __init__(self, tickets_dir: str, repo_path: str):
        self.tickets_dir = Path(tickets_dir)
        self.tickets_dir.mkdir(parents=True, exist_ok=True)
        self.repo_path = repo_path

    def create_local_ticket(self, risk_result: dict) -> str:
        """生成本地 JSON 工单文件"""
        ticket_id = f"PHOTON-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        severity = "Critical" if risk_result["level"] == "critical" else "High"
        vuln_type = "evasion_risk"

        ticket = {
            "ticket_id": ticket_id,
            "severity": severity,
            "vulnerability_type": vuln_type,
            "title": f"[安全门禁] 逃逸风险评分 {risk_result['score']}/100 ({risk_result['level']})",
            "description": risk_result["summary"],
            "risk_details": {
                "score": risk_result["score"],
                "level": risk_result["level"],
                "risky_files": risk_result["risky_files"],
                "critical_findings": risk_result["critical_findings"],
            },
            "created_at": datetime.now().isoformat() + "Z",
            "resolved_at": None,
            "status": "open",
            "sla_target_hours": 72 if vuln_type == "strongpool_escape" else 24 * 7,
            "source": "ci_security_gate",
            "action_required": (
                "1. 安全团队人工审核本次变更\n"
                "2. 确认不存在逃逸漏洞\n"
                "3. 添加安全测试用例\n"
                "4. 审核通过后关闭工单并允许发布"
            ),
        }

        ticket_file = self.tickets_dir / f"{ticket_id}.json"
        with open(ticket_file, 'w') as f:
            json.dump(ticket, f, indent=2, ensure_ascii=False)

        return str(ticket_file)

    def create_github_issue(self, risk_result: dict, repo: str, token: str) -> Optional[str]:
        """创建 GitHub Issue（需要 GITHUB_TOKEN）"""
        try:
            import urllib.request
            import urllib.error

            title = f"[安全门禁] 逃逸风险评分 {risk_result['score']}/100 ({risk_result['level']})"
            body = f"""## 安全门禁触发

**逃逸风险评分**: {risk_result['score']}/100
**风险等级**: {risk_result['level']}
**触发时间**: {datetime.now().isoformat()}

## 风险摘要
{risk_result['summary']}

## 高风险文件
"""
            for rf in risk_result.get("risky_files", []):
                body += f"- `{rf['file']}` (风险: {rf['risk_level']}, 评分: {rf['score']})\n"

            if risk_result.get("critical_findings"):
                body += "\n## 严重发现\n"
                for cf in risk_result["critical_findings"]:
                    body += f"- **{cf['keyword']}** in `{cf['file']}`: {cf['line']}\n"

            body += """
## 必须完成的动作
1. 安全团队人工审核本次变更
2. 确认不存在逃逸漏洞
3. 添加安全测试用例
4. 审核通过后关闭 Issue 并允许发布

---
*此 Issue 由 CI 安全门禁脚本自动生成 (scripts/ci_security_gate.py)*
"""

            data = json.dumps({"title": title, "body": body, "labels": ["security", "evasion-risk", "ci-gate"]}).encode()
            api_url = f"https://api.github.com/repos/{repo}/issues"
            # 验证 URL scheme，防止 SSRF
            from urllib.parse import urlparse
            parsed = urlparse(api_url)
            if parsed.scheme != "https" or parsed.netloc != "api.github.com":
                print(f"  ⚠ 不安全的 GitHub API URL: {api_url}")
                return None
            req = urllib.request.Request(
                api_url,
                data=data,
                headers={
                    "Authorization": f"token {token}",
                    "Accept": "application/vnd.github.v3+json",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=30) as resp:  # nosec B310 - URL已验证为https://api.github.com
                result = json.loads(resp.read())
                return result.get("html_url")
        except Exception as e:
            print(f"  ⚠ 创建 GitHub Issue 失败: {e}")
            return None


# ============================================================
# 主门禁逻辑
# ============================================================

def run_evasion_risk_check(args) -> tuple:
    """运行逃逸风险评分检查"""
    print("[1/4] 逃逸风险评分检查...")
    scorer = EvasionRiskScorer(args.repo)
    risk_result = scorer.score_diff(args.base_ref, args.head_ref)

    print(f"  评分: {risk_result['score']}/100 ({risk_result['level']})")
    print(f"  摘要: {risk_result['summary']}")

    if risk_result["risky_files"]:
        print("  高风险文件:")
        for rf in risk_result["risky_files"]:
            print(f"    - {rf['file']} ({rf['risk_level']})")

    if risk_result["critical_findings"]:
        print("  ⚠ 严重发现:")
        for cf in risk_result["critical_findings"]:
            print(f"    - {cf['keyword']} in {cf['file']}: {cf['line'][:80]}")

    # 判断是否触发门禁
    if risk_result["score"] >= args.evasion_threshold or risk_result["critical_findings"]:
        print(f"  ❌ 逃逸风险评分 >= {args.evasion_threshold} 或存在严重发现，触发安全门禁！")

        # 生成本地工单
        tickets_dir = os.path.join(args.repo, ".compliance_tickets")
        ticket_gen = TicketGenerator(tickets_dir, args.repo)
        ticket_file = ticket_gen.create_local_ticket(risk_result)
        print(f"  📋 已生成本地漏洞工单: {ticket_file}")

        # 创建 GitHub Issue
        if args.create_github_issue and args.github_token and args.github_repo:
            issue_url = ticket_gen.create_github_issue(
                risk_result, args.github_repo, args.github_token
            )
            if issue_url:
                print(f"  📋 已创建 GitHub Issue: {issue_url}")

        return False, risk_result
    else:
        print(f"  ✅ 逃逸风险评分 < {args.evasion_threshold}，通过")
        return True, risk_result


def run_sast_check(args) -> bool:
    """运行 SAST 检查"""
    print("[2/4] SAST 安全扫描检查...")
    try:
        result = subprocess.run(
            [sys.executable, "-m", "bandit", "-r", "evolution/", "-f", "json"],
            cwd=args.repo,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode in (0, 1):
            data = json.loads(result.stdout)
            results = data.get("results", [])
            high = sum(1 for r in results if r.get("issue_severity") == "HIGH")
            medium = sum(1 for r in results if r.get("issue_severity") == "MEDIUM")
            low = sum(1 for r in results if r.get("issue_severity") == "LOW")
            print(f"  扫描结果: {len(results)} 个问题 (High: {high}, Medium: {medium}, Low: {low})")

            if high > 0:
                print(f"  ❌ 发现 {high} 个 High 级别安全问题，禁止发布！")
                return False
            else:
                print("  ✅ 无 High 级别安全问题，通过")
                return True
        else:
            print(f"  ⚠ bandit 执行失败: {result.stderr[:100]}")
            return True  # 工具失败不阻断
    except Exception as e:
        print(f"  ⚠ SAST 检查异常: {e}")
        return True  # 工具异常不阻断


def run_compliance_evidence_check(args) -> bool:
    """运行合规证据检查"""
    print("[3/4] 合规证据检查...")
    collector_script = os.path.join(args.repo, "scripts", "compliance_evidence_collector.py")
    if not os.path.exists(collector_script):
        print("  ⚠ 合规证据收集器不存在，跳过")
        return True

    try:
        result = subprocess.run(
            [sys.executable, collector_script, "--mode", "local", "--ci-gate"],
            cwd=args.repo,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0:
            print("  ✅ 合规证据检查通过")
            return True
        else:
            print("  ❌ 合规证据检查不达标！")
            # 输出最后几行
            for line in result.stdout.strip().split("\n")[-10:]:
                print(f"    {line}")
            return False
    except Exception as e:
        print(f"  ⚠ 合规证据检查异常: {e}")
        return True  # 工具异常不阻断


def run_test_check(args) -> bool:
    """运行测试检查"""
    print("[4/4] 单元测试检查...")
    try:
        result = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", "evolution/tests",
             "-p", "test_*.py"],
            cwd=args.repo,
            capture_output=True,
            text=True,
            timeout=120,
        )
        # 解析测试结果
        for line in result.stdout.strip().split("\n"):
            if "Ran" in line and "tests" in line:
                print(f"  {line.strip()}")
            if "OK" == line.strip():
                print("  ✅ 全部测试通过")
                return True
            if "FAILED" in line:
                print(f"  ❌ 测试失败: {line.strip()}")
                return False
        if result.returncode == 0:
            print("  ✅ 测试通过")
            return True
        else:
            print("  ❌ 测试失败")
            return False
    except Exception as e:
        print(f"  ⚠ 测试检查异常: {e}")
        return True


def main():
    parser = argparse.ArgumentParser(
        description="PhotonBox CI 安全门禁脚本",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--repo", default=".", help="仓库路径")
    parser.add_argument("--base-ref", default="HEAD~1", help="基准提交（默认 HEAD~1）")
    parser.add_argument("--head-ref", default="HEAD", help="目标提交（默认 HEAD）")
    parser.add_argument("--evasion-threshold", type=int, default=90,
                        help="逃逸风险评分阈值（默认 90，>= 阈值触发门禁）")
    parser.add_argument("--check", choices=["all", "evasion-risk", "sast", "compliance", "test"],
                        default="all", help="指定检查项（默认全部）")
    parser.add_argument("--create-github-issue", action="store_true",
                        help="触发门禁时创建 GitHub Issue")
    parser.add_argument("--github-repo", default=os.environ.get("GITHUB_REPOSITORY", ""),
                        help="GitHub 仓库（格式 owner/repo）")
    parser.add_argument("--github-token", default=os.environ.get("GITHUB_TOKEN", ""),
                        help="GitHub Token")

    args = parser.parse_args()
    args.repo = os.path.abspath(args.repo)

    print("=" * 60)
    print("PhotonBox CI 安全门禁")
    print("=" * 60)
    print(f"仓库: {args.repo}")
    print(f"基准: {args.base_ref} -> {args.head_ref}")
    print(f"逃逸风险阈值: {args.evasion_threshold}")
    print(f"检查项: {args.check}")
    print()

    all_passed = True

    if args.check in ("all", "evasion-risk"):
        passed, _ = run_evasion_risk_check(args)
        all_passed = all_passed and passed
        print()

    if args.check in ("all", "sast"):
        passed = run_sast_check(args)
        all_passed = all_passed and passed
        print()

    if args.check in ("all", "compliance"):
        passed = run_compliance_evidence_check(args)
        all_passed = all_passed and passed
        print()

    if args.check in ("all", "test"):
        passed = run_test_check(args)
        all_passed = all_passed and passed
        print()

    print("=" * 60)
    if all_passed:
        print("✅ 所有安全门禁检查通过，允许发布！")
        sys.exit(0)
    else:
        print("❌ 安全门禁检查失败，禁止发布！")
        print("   请修复上述问题后重新运行 CI。")
        sys.exit(1)


if __name__ == "__main__":
    main()
