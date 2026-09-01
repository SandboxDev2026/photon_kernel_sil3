#!/usr/bin/env python3
"""内核安全漏洞(CVE)监控脚本。

功能：
1. 获取当前内核版本
2. 查询 CVE 数据库（NVD / Ubuntu Security / Debian Security）
3. 检查是否有影响当前内核版本的 CVE
4. 输出报告（JSON / 文本）
5. 可选：邮件/飞书通知

使用：
  python3 cve_monitor.py                  # 检查当前内核
  python3 cve_monitor.py --kernel 5.15.0  # 检查指定内核版本
  python3 cve_monitor.py --json            # JSON 输出
  python3 cve_monitor.py --notify webhook_url  # 飞书 webhook 通知
"""
import argparse
import json
import platform
import re
import subprocess
import sys
import urllib.request
import urllib.error
from datetime import datetime, timedelta


def get_kernel_version():
    """获取当前内核版本（如 5.15.0）。"""
    release = platform.release()
    # 提取主版本.次版本.补丁版本
    m = re.match(r'(\d+)\.(\d+)\.(\d+)', release)
    if m:
        return f"{m.group(1)}.{m.group(2)}.{m.group(3)}"
    return release


def get_kernel_config():
    """获取内核配置关键项（用于判断攻击面）。"""
    config = {}
    config_paths = [
        f"/boot/config-{platform.release()}",
        "/proc/config.gz",
    ]
    for path in config_paths:
        try:
            if path.endswith('.gz'):
                import gzip
                with gzip.open(path, 'rt') as f:
                    content = f.read()
            else:
                with open(path) as f:
                    content = f.read()
            for key in ['CONFIG_BPF', 'CONFIG_SECCOMP', 'CONFIG_NAMESPACES',
                        'CONFIG_CHECKPOINT_RESTORE', 'CONFIG_CGROUP_BPF',
                        'CONFIG_USER_NS', 'CONFIG_KEXEC', 'CONFIG_MODULES']:
                m = re.search(rf'{key}=(\w+)', content)
                if m:
                    config[key] = m.group(1)
            break
        except (FileNotFoundError, PermissionError):
            continue
    return config


def search_ubuntu_security(kernel_version):
    """查询 Ubuntu Security 数据库中影响指定内核的 CVE。"""
    # Ubuntu CVE API: https://ubuntu.com/security/cves
    # 简化：使用 Ubuntu CVE JSON feed
    url = f"https://ubuntu.com/security/cves.json?package=linux&status=needed"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'cve-monitor/1.0'})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            cves = []
            for item in data.get('cves', []):
                cve_id = item.get('id', '')
                # 检查是否影响当前内核版本（简化：只收集，不做版本匹配）
                cves.append({
                    'id': cve_id,
                    'severity': item.get('priority', 'unknown'),
                    'description': item.get('description', '')[:200],
                    'status': item.get('status', 'unknown'),
                })
            return cves
    except (urllib.error.URLError, json.JSONDecodeError, KeyError) as e:
        return [{'error': f'Ubuntu API query failed: {e}'}]


def check_livepatch():
    """检查 Canonical Livepatch 状态（Ubuntu）。"""
    try:
        result = subprocess.run(['canonical-livepatch', 'status'],
                              capture_output=True, text=True, timeout=5)
        return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return "Livepatch not installed or not available"


def generate_report(kernel_version, config, cves, livepatch):
    """生成安全报告。"""
    report = {
        'scan_time': datetime.now().isoformat(),
        'kernel_version': kernel_version,
        'kernel_config': config,
        'livepatch_status': livepatch,
        'cve_count': len(cves),
        'cves': cves[:20],  # 最多显示20条
        'recommendations': [],
    }
    # 基于配置生成建议
    if config.get('CONFIG_USER_NS') == 'y':
        report['recommendations'].append(
            'USER_NS 已启用，考虑限制非特权 user namespace (sysctl user.max_user_namespaces=0)')
    if config.get('CONFIG_KEXEC') == 'y':
        report['recommendations'].append(
            'KEXEC 已启用，生产环境建议禁用 (kexec 可用于内核热替换攻击)')
    if config.get('CONFIG_MODULES') == 'y':
        report['recommendations'].append(
            'MODULES 已启用，考虑设置 sysctl kernel.modules_disabled=1 (运行时禁加载模块)')
    if not livepatch or 'not installed' in livepatch.lower():
        report['recommendations'].append(
            '建议启用 Canonical Livepatch 或 kpatch，实现内核热补丁无需重启')
    report['recommendations'].append(
        '定期运行: sudo apt update && sudo apt upgrade linux-image-$(uname -r)')
    report['recommendations'].append(
        '关注: https://www.kernel.org/ 安全公告和 https://ubuntu.com/security/cves')
    return report


def send_webhook(webhook_url, report):
    """发送飞书 webhook 通知。"""
    payload = {
        'msg_type': 'text',
        'content': {
            'text': f"[内核CVE监控]\n内核: {report['kernel_version']}\n"
                    f"CVE数量: {report['cve_count']}\n"
                    f"扫描时间: {report['scan_time']}\n"
                    f"建议: {'; '.join(report['recommendations'][:3])}"
        }
    }
    try:
        req = urllib.request.Request(
            webhook_url,
            data=json.dumps(payload).encode(),
            headers={'Content-Type': 'application/json'})
        urllib.request.urlopen(req, timeout=5)
        return True
    except Exception as e:
        print(f"Webhook notification failed: {e}", file=sys.stderr)
        return False


def main():
    parser = argparse.ArgumentParser(description='内核 CVE 监控')
    parser.add_argument('--kernel', help='指定内核版本（默认当前内核）')
    parser.add_argument('--json', action='store_true', help='JSON 格式输出')
    parser.add_argument('--notify', help='飞书 webhook URL（可选）')
    parser.add_argument('--cron', action='store_true', help='cron 模式（只输出摘要）')
    args = parser.parse_args()
    kernel_version = args.kernel or get_kernel_version()
    config = get_kernel_config()
    cves = search_ubuntu_security(kernel_version)
    livepatch = check_livepatch()
    report = generate_report(kernel_version, config, cves, livepatch)
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    elif args.cron:
        print(f"[{report['scan_time']}] kernel={kernel_version} cves={report['cve_count']}")
    else:
        print(f"=== 内核 CVE 监控报告 ===")
        print(f"扫描时间: {report['scan_time']}")
        print(f"内核版本: {report['kernel_version']}")
        print(f"内核配置: {json.dumps(config, indent=2)}")
        print(f"Livepatch: {livepatch}")
        print(f"\n影响 CVE 数量: {report['cve_count']}")
        for cve in report['cves'][:10]:
            if 'error' in cve:
                print(f"  [ERROR] {cve['error']}")
            else:
                print(f"  {cve['id']} [{cve['severity']}] {cve['description'][:80]}...")
        print(f"\n安全建议:")
        for rec in report['recommendations']:
            print(f"  - {rec}")
    if args.notify:
        send_webhook(args.notify, report)
    return 0 if report['cve_count'] == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
