"""配置加载:config.toml + 默认值 + 路径解析."""

from __future__ import annotations

import copy
import errno
import math
import os
import tomllib
from string import Formatter
from pathlib import Path
from urllib.parse import urlsplit

from .paths import WRITE_LOCK_NAME, check_file_paths, path_key

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_OUTPUT_DIR = "data/subscriptions"
RULE_NAMES = ("reject", "direct", "proxy", "cncidr")
LOG_BACKUPS = 3
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_TOKEN_FILE_BYTES = 65536

DEFAULTS: dict = {
    "api": {
        "token": "auto",
        "token_file": "",
        # 实际服务域名仅保存在本机配置,公开源码使用保留域名示例.
        "api_urls": ["https://api.example.invalid"],
        "cloudapi_urls": [],
        "fetch_account_info": True,
        "request_timeout": 15,
        "max_response_bytes": MAX_RESPONSE_BYTES,
        "retry_per_url": 1,
        "tls_verify": False,
        # 订阅链接(clash 配置):转换时从中提取分流规则写入生成的 clash.yaml
        "subscription_url": "",
    },
    "data": {
        # 只保留一份有效的原始 JSON(下载且校验有效才覆盖)
        "raw_file": "data/latest-wwss-nodes.json",
        # 可在本机配置中覆盖为 qx-sub-converter 的静态目录.
        "output_dir": DEFAULT_OUTPUT_DIR,
    },
    "output": {
        "clash_file": "WestWorldVPN-clash.yaml",
        "quantumultx_file": "WestWorldVPN-quantumultx.txt",
        "backup_old": True,
        "include_quantumultx_group": True,
        "include_account_info": False,
        # 保持官方客户端兼容行为;可显式开启节点证书校验.
        "tls_verify": False,
    },
    "schedule": {
        # 执行失败后的重试间隔(分钟,可为小数便于测试)
        "retry_interval_minutes": 5.0,
        # 最多尝试次数(含首次)
        "max_attempts": 3,
    },
    "rules": {
        "tls_verify": True,
        # 分流规则来源:github(rule-providers,推荐) | subscription(机场订阅) | builtin(内置极简)
        "preset": "github",
        # 规则文件落盘目录(供 Clash Verge 运行时经 rule-providers 拉取)
        "output_dir": "data/rules",
        # rule-providers 引用的基础 URL(本机 Flask 静态服务;外网可换 ngrok 地址)
        "provider_base_url": "http://127.0.0.1:8000/pages/rules/",
        # 镜像列表(按序尝试,{name} 为规则名);默认 jsdelivr CDN 优先 + GitHub 直连兜底
        "mirror_urls": [
            "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/{name}.txt",
            "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/{name}.txt",
        ],
        # 本地规则超过 N 天未更新则重新下载
        "refresh_days": 7,
    },
    "log": {
        "file": "logs/subloader.log",
        "level": "info",
    },
}


def _merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in override.items():
        # TOML 没有 null;配置文件可用空字符串表示沿用默认值.
        # 环境变量在合并后应用,空的凭据环境变量仍按显式覆盖处理.
        if value == "" and key in base and not isinstance(base[key], dict):
            continue
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def is_http_url(value: object) -> bool:
    if (not isinstance(value, str) or not value
            or any(c.isspace() or ord(c) < 32 or 127 <= ord(c) <= 159 for c in value)):
        return False
    try:
        parsed = urlsplit(value)
        return (parsed.scheme in ("http", "https") and bool(parsed.hostname)
                and parsed.username is None and parsed.password is None
                and not parsed.fragment and parsed.port != 0)
    except ValueError:
        return False


def resolve_path(value: str | Path) -> Path:
    """把配置里的路径解析为绝对路径:~ 展开,相对路径基于项目根."""
    p = Path(os.path.expanduser(str(value)))
    if not p.is_absolute():
        p = PROJECT_ROOT / p
    return p


class Config:
    def __init__(self, data: dict, path: Path | None):
        self._data = data
        self.path = path

    # -- 便捷访问 ----------------------------------------------------
    def __getitem__(self, section: str) -> dict:
        return self._data[section]

    def get(self, section: str, key: str, default=None):
        return self._data.get(section, {}).get(key, default)

    # -- 常用路径 ----------------------------------------------------
    @property
    def token_file(self) -> Path | None:
        value = self.get("api", "token_file", "")
        return resolve_path(value) if value else None

    @property
    def raw_file(self) -> Path:
        return resolve_path(self._data["data"]["raw_file"])

    @property
    def output_dir(self) -> Path:
        return resolve_path(self._data["data"]["output_dir"])

    @property
    def clash_path(self) -> Path:
        return self.output_dir / self._data["output"]["clash_file"]

    @property
    def quantumultx_path(self) -> Path:
        return self.output_dir / self._data["output"]["quantumultx_file"]

    @property
    def log_path(self) -> Path:
        return resolve_path(self._data["log"]["file"])

    def validate(self) -> list[str]:
        errors: list[str] = []
        for section in DEFAULTS:
            if not isinstance(self._data.get(section), dict):
                errors.append("[%s] 必须是配置表" % section)
        if errors:
            return errors

        def number(section, key, minimum, maximum, integer=False):
            value = self.get(section, key)
            valid_type = type(value) is int if integer else type(value) in (int, float)
            try:
                valid = valid_type and math.isfinite(value) and minimum <= value <= maximum
            except OverflowError:
                valid = False
            if not valid:
                errors.append("[%s] %s 必须是 %s 到 %s 之间的%s" % (
                    section, key, minimum, maximum, "整数" if integer else "有限数值"))

        number("api", "request_timeout", 0.001, 300)
        number("api", "max_response_bytes", 1, 64 * 1024 * 1024, integer=True)
        number("api", "retry_per_url", 0, 10, integer=True)
        number("schedule", "max_attempts", 1, 20, integer=True)
        number("schedule", "retry_interval_minutes", 0, 1440)
        number("rules", "refresh_days", 0, 3650)

        for section, key in (("api", "tls_verify"), ("api", "fetch_account_info"),
                             ("output", "backup_old"), ("output", "include_quantumultx_group"),
                             ("output", "tls_verify"), ("output", "include_account_info"),
                             ("rules", "tls_verify")):
            if type(self.get(section, key)) is not bool:
                errors.append("[%s] %s 必须是布尔值" % (section, key))
        token = self.get("api", "token")
        if (not isinstance(token, str) or not token.strip()
                or (isinstance(token, str) and any(ord(c) < 32 or ord(c) == 127 for c in token))):
            errors.append("[api] token 必须是 auto 或非空字符串")
        token_file = self.get("api", "token_file", "")
        if (not isinstance(token_file, str) or (token_file and not token_file.strip())
                or (isinstance(token_file, str) and "\x00" in token_file)):
            errors.append("[api] token_file 必须为空或有效文件路径")

        for key in ("api_urls", "cloudapi_urls"):
            urls = self.get("api", key)
            if (not isinstance(urls, list) or (key == "api_urls" and not urls)
                    or (isinstance(urls, list) and any(
                        not is_http_url(u) or urlsplit(u).query for u in urls))):
                errors.append("[api] %s 必须是无查询参数的有效 HTTP(S) URL 列表" % key)
        sub_url = self.get("api", "subscription_url")
        if sub_url != "" and not is_http_url(sub_url):
            errors.append("[api] subscription_url 必须为空或有效的 HTTP(S) URL")
        if self.get("rules", "preset") not in ("github", "subscription", "builtin"):
            errors.append("[rules] preset 必须为 github / subscription / builtin")
        provider_url = self.get("rules", "provider_base_url")
        if not is_http_url(provider_url) or urlsplit(provider_url).query:
            errors.append("[rules] provider_base_url 必须是无查询参数的有效 HTTP(S) URL")
        mirrors = self.get("rules", "mirror_urls")
        if not isinstance(mirrors, list):
            errors.append("[rules] mirror_urls 必须是 URL 模板列表,留空列表使用默认镜像")
        else:
            for template in mirrors:
                try:
                    if not isinstance(template, str):
                        raise ValueError
                    fields = [(field, spec, conversion) for _, field, spec, conversion
                              in Formatter().parse(template) if field is not None]
                    if (not fields or any(field != "name" or spec or conversion for field, spec, conversion in fields)
                            or not is_http_url(template.format(name="reject"))):
                        raise ValueError
                except (ValueError, KeyError, IndexError, AttributeError, TypeError):
                    errors.append("[rules] mirror_urls 模板须为有效 HTTP(S) URL 且包含 {name}")
                    break

        for section, key in (("data", "raw_file"), ("data", "output_dir"),
                             ("rules", "output_dir"), ("log", "file")):
            value = self.get(section, key)
            if not isinstance(value, str) or not value.strip() or "\x00" in value:
                errors.append("[%s] %s 必须是非空路径" % (section, key))
        for key in ("clash_file", "quantumultx_file"):
            value = self.get("output", key)
            if (not isinstance(value, str) or not value.strip() or "\x00" in value
                    or value in (".", "..") or Path(value).name != value):
                errors.append("[output] %s 必须是文件名,不能包含目录" % key)
        if str(self.get("log", "level")).lower() not in ("debug", "info", "warning", "error", "critical"):
            errors.append("[log] level 必须是有效的日志级别")
        if not errors:
            try:
                rules_dir = resolve_path(self.get("rules", "output_dir"))
                paths = [self.raw_file, self.clash_path, self.quantumultx_path]
                files = paths + [p.with_suffix(p.suffix + ".bak") for p in paths]
                files += [self.log_path] + [Path(str(self.log_path) + ".%d" % n)
                                            for n in range(1, LOG_BACKUPS + 1)]
                files += [rules_dir / (name + ".yaml") for name in RULE_NAMES]
                if self.token_file is not None:
                    files.append(self.token_file)
                directories = [self.raw_file.parent, self.output_dir, self.log_path.parent, rules_dir]
                locks = [self.raw_file.parent / "subloader.lock", rules_dir / ".subloader.lock"]
                locks += list({path_key(p): p for p in (d / WRITE_LOCK_NAME for d in directories)}.values())
                check_file_paths(files + locks, directories,
                                 [self.path or PROJECT_ROOT / "config.toml", PROJECT_ROOT / "config.toml",
                                  PROJECT_ROOT / "login.local.toml"])
            except (OSError, RuntimeError, ValueError):
                errors.append("运行文件、备份、日志轮转、规则缓存、锁、目录或配置文件存在路径冲突或无法解析")
        return errors


def load_config(path: Path | str | None = None) -> Config:
    """加载配置;未指定路径时依次尝试 项目根/config.toml."""
    explicit = path is not None
    if not explicit:
        path = PROJECT_ROOT / "config.toml"
    path = Path(path).expanduser()
    try:
        # Python 3.13 起,非严格解析不再报告符号链接循环.
        path = path.resolve(strict=True)
    except FileNotFoundError:
        path = path.resolve()
    except RuntimeError as exc:  # Python 3.11 / 3.12
        raise ValueError("配置路径存在符号链接循环") from exc
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ValueError("配置路径存在符号链接循环") from exc
        raise
    data: dict = {}
    if path.exists():
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    elif explicit:
        raise FileNotFoundError("指定的配置文件不存在: %s" % path)
    merged = _merge(DEFAULTS, data)
    for variable, key in (("SUBLOADER_TOKEN", "token"),
                          ("SUBLOADER_SUBSCRIPTION_URL", "subscription_url")):
        if variable in os.environ and isinstance(merged.get("api"), dict):
            merged["api"][key] = os.environ[variable]
    return Config(merged, path if path.exists() else None)
