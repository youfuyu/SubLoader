#!/usr/bin/env python3
"""检查 Git 暂存区,只输出文件位置和问题类别,从不回显凭据."""

from __future__ import annotations

import fnmatch
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tomllib
from typing import NamedTuple
from urllib.parse import quote, urlsplit


PRIVATE_DIRS = {
    '.venv', 'venv', 'env', '__pycache__', '.workbuddy', '.codex', '.idea', '.vscode',
    'data', 'logs', 'output', 'outputs', 'subscriptions', 'artifacts', 'build', 'dist',
}
PRIVATE_PATTERNS = (
    '*.bak', '*.tmp', '*.backup', '*.rollback', '*.log', '*.log.[0-9]*', '*.lock',
    '*.pem', '*.key', '*.p12', '*.pfx', '*.db', '*.sqlite', '*.sqlite3',
    'id_rsa*', 'id_ed25519*', 'credentials*.json', 'secrets*.json',
    '*.zip', '*.tar', '*.tar.gz', 'latest-wwss-nodes.json',
    'WestWorldVPN-clash.yaml', 'WestWorldVPN-quantumultx.txt',
    '.DS_Store',
)
PATTERNS = {
    '私钥内容': re.compile(r'-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----'),
    'GitHub 凭据': re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b'),
    '访问密钥': re.compile(r'\b(?:AKIA[0-9A-Z]{16}|sk-(?:proj-)?[A-Za-z0-9_-]{32,})\b'),
    '本机用户路径': re.compile(r'/(?:Users|home)/[^/\s"\']+'),
    '个人隧道地址': re.compile(r'https?://[^/\s"\']+\.(?:ngrok-free\.(?:app|dev)|ngrok\.io|trycloudflare\.com)'),
    '私有订阅路径': re.compile(r'/rss/[^/\s"\']+/[A-Za-z0-9_-]{5,}(?:/[A-Za-z0-9_-]{5,})?'),
}
EMAIL = re.compile(r'[A-Za-z0-9_.+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})')
ASSIGNMENT = re.compile(
    r'''(?<![A-Za-z0-9_-])["']?(?P<key>[A-Za-z_][A-Za-z0-9_-]*)["']?\s*[:=]\s*'''
    r'''(?:"(?P<double>[^"\r\n]*)"|'(?P<single>[^'\r\n]*)'|(?P<bare>[^\s\#;,}\]"']+))''')


def credential_assignment(match, path: str) -> bool:
    key = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', match.group('key')).lower().replace('-', '_')
    if not re.search(r'(?:^|_)(?:token|password|passwd|pwd|secret|api_key|apikey|subscription_url)$', key):
        return False
    value = next((match.group(name) for name in ('double', 'single', 'bare')
                  if match.group(name) is not None), '')
    if value.startswith('${') and value.endswith('}'):
        return False
    if key.endswith('subscription_url') and value.startswith(('http://', 'https://')):
        return not example_domain(urlsplit(value).hostname or '')
    # Python 中的未加引号值通常是变量或表达式;dotenv/shell 等仍检查裸值.
    if match.group('bare') is not None and path.endswith('.py'):
        return False
    return len(value) >= 24 and bool(re.fullmatch(r'[A-Za-z0-9/+_.=-]+', value))


class Finding(NamedTuple):
    path: str
    line: int
    reason: str


def private_path(name: str) -> bool:
    path = PurePosixPath(name)
    if path.name in {'config.example.toml', '.env.example', 'uv.lock'}:
        return any(part.casefold() in PRIVATE_DIRS for part in path.parts[:-1])
    name = path.name.casefold()
    return (any(part.casefold() in PRIVATE_DIRS for part in path.parts)
            or name.startswith('.env')
            or fnmatch.fnmatchcase(name, 'config*.toml')
            or name.endswith('.local.toml')
            or any(fnmatch.fnmatchcase(name, pattern.casefold()) for pattern in PRIVATE_PATTERNS))


def example_domain(domain: str) -> bool:
    domain = domain.lower().rstrip('.')
    return (domain in {'example.com', 'example.net', 'example.org', 'localhost'}
            or domain.endswith(('.invalid', '.example', '.example.com', '.example.net', '.example.org')))


def scan_text(path: str, content: str, local_values=()) -> list[Finding]:
    findings = []
    for number, line in enumerate(content.splitlines(), 1):
        for reason, pattern in PATTERNS.items():
            if pattern.search(line):
                findings.append(Finding(path, number, reason))
        if any(credential_assignment(match, path) for match in ASSIGNMENT.finditer(line)):
            findings.append(Finding(path, number, '硬编码凭据'))
        if any(not example_domain(match.group(1)) for match in EMAIL.finditer(line)):
            findings.append(Finding(path, number, '非示例邮箱地址'))
        if any(value in line for value in local_values):
            findings.append(Finding(path, number, '与本机私有配置或节点数据匹配'))
    return findings


def local_private_values(root: Path) -> set[str]:
    """仅在内存中提取本项目私有值;不读取系统偏好、密钥链或项目外文件."""
    values = set()
    def remember(value):
        if isinstance(value, str) and len(value) >= 8:
            values.update({value, json.dumps(value, ensure_ascii=False)[1:-1], quote(value, safe='')})

    config_path = root / 'config.toml'
    if config_path.exists():
        config = tomllib.loads(config_path.read_text(encoding='utf-8'))
        api = config.get('api', {})
        remember(api.get('token'))
        subscription = api.get('subscription_url', '')
        remember(subscription)
        if isinstance(subscription, str):
            for segment in urlsplit(subscription).path.split('/'):
                if len(segment) >= 5 and segment not in {'subscribe', 'subscription'}:
                    values.add(segment)
        for field in ('api_urls', 'cloudapi_urls'):
            for value in api.get(field, []):
                remember(value)
        raw_path = Path(config.get('data', {}).get('raw_file', 'data/latest-wwss-nodes.json')).expanduser()
        if not raw_path.is_absolute():
            raw_path = root / raw_path
    else:
        raw_path = root / 'data/latest-wwss-nodes.json'

    raw_path = raw_path.resolve()
    if raw_path.is_relative_to(root.resolve()) and raw_path.is_file():
        if raw_path.stat().st_size > 64 * 1024 * 1024:
            raise ValueError('本机原始文件过大,需要人工审查')
        raw = json.loads(raw_path.read_text(encoding='utf-8'))
        def visit(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    if key in {'password', 'token', 'email', 'server', 'server_ip', 'quick_url'}:
                        remember(child)
                    if isinstance(child, (list, dict)):
                        visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)
        visit(raw)
    for variable in ('SUBLOADER_TOKEN', 'SUBLOADER_SUBSCRIPTION_URL'):
        remember(os.environ.get(variable))
    return values


def git(root, *args):
    return subprocess.run(['git', '-C', str(root), *args], check=True, capture_output=True).stdout


def check_index(root: Path) -> tuple[int, list[Finding]]:
    values = local_private_values(root)
    entries = git(root, 'ls-files', '--stage', '-z').split(b'\0')
    findings = []
    count = 0
    for entry in entries:
        if not entry:
            continue
        metadata, path_bytes = entry.split(b'\t', 1)
        mode, blob, stage = metadata.decode('ascii').split()
        path = os.fsdecode(path_bytes)
        count += 1
        if private_path(path):
            findings.append(Finding(path, 0, '禁止提交的本机或运行文件'))
            continue
        if stage != '0' or mode not in {'100644', '100755'}:
            findings.append(Finding(path, 0, '未合并条目、符号链接或子模块需要人工审查'))
            continue
        if int(git(root, 'cat-file', '-s', blob)) > 2 * 1024 * 1024:
            findings.append(Finding(path, 0, '文件超过源码发布大小限制'))
            continue
        try:
            content = git(root, 'cat-file', 'blob', blob).decode('utf-8')
        except UnicodeDecodeError:
            findings.append(Finding(path, 0, '二进制文件需要人工审查'))
            continue
        findings.extend(scan_text(path, content, values))
    return count, findings


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    try:
        count, findings = check_index(root)
    except (OSError, ValueError, TypeError, subprocess.CalledProcessError):
        print('发布检查未完成:请检查 Git 状态及本机配置/原始 JSON 格式;未输出私有内容。', file=sys.stderr)
        return 2
    for finding in findings:
        print('%s:%d: %s' % finding, file=sys.stderr)
    if findings:
        print('发布检查失败,请移除或脱敏上述暂存文件。', file=sys.stderr)
        return 1
    if count == 0:
        print('暂无暂存文件,尚未形成可检查的发布内容。', file=sys.stderr)
        return 2
    print('发布检查通过:已检查 %d 个暂存文件,未发现已知敏感信息。' % count)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
