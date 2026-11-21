"""分流规则下载模块(独立脚本): ./run.sh rules 或 python -m core.rules

从 GitHub(Loyalsoldier/clash-rules)下载四类规则,经镜像加速,落到本地静态目录,
供生成的 clash.yaml 以 rule-providers 引用(Clash Verge 运行时自动按 interval 更新):
  reject.yaml  广告/追踪域名 -> REJECT
  direct.yaml  国内域名      -> DIRECT
  proxy.yaml   国外域名      -> PROXY
  cncidr.yaml  国内 IP 段    -> DIRECT
"""

from __future__ import annotations

import datetime
import ipaddress
import logging
import sys
import time
from pathlib import Path

import yaml

from . import store
from .config import Config, MAX_RESPONSE_BYTES, RULE_NAMES, resolve_path
from .fetcher import _build_opener, _http_get_raw

log = logging.getLogger("core.rules")

RULE_FILES = {name: {"behavior": "ipcidr" if name == "cncidr" else "domain"}
              for name in RULE_NAMES}
MIN_PAYLOAD = 100  # 校验阈值:低于此行数视为坏文件


def rules_dir(cfg: Config) -> Path:
    return resolve_path(cfg.get("rules", "output_dir", "data/rules"))


def _validate_rule_text(text: str, name: str) -> list:
    data = yaml.load(text, Loader=getattr(yaml, "CSafeLoader", yaml.SafeLoader))
    payload = data.get("payload") if isinstance(data, dict) else None
    if (not isinstance(payload, list) or len(payload) < MIN_PAYLOAD
            or any(not isinstance(item, str) or not item.strip() for item in payload)):
        raise ValueError("规则 payload 必须是至少 %d 条的非空字符串列表" % MIN_PAYLOAD)
    if RULE_FILES[name]["behavior"] == "ipcidr":
        for item in payload:
            ipaddress.ip_network(item, strict=False)
    return payload


def _download_one(cfg: Config, name: str) -> bool:
    """从镜像列表依次尝试下载单个规则文件;成功且校验通过才落盘."""
    mirrors = cfg.get("rules", "mirror_urls") or [
        "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/{name}.txt",
        "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/{name}.txt",
    ]
    timeout = float(cfg.get("api", "request_timeout", 15))
    opener = _build_opener(bool(cfg.get("rules", "tls_verify", True)))

    for template in mirrors:
        try:
            url = template.format(name=name)
            text = _http_get_raw(opener, url, timeout,
                                max_bytes=cfg.get("api", "max_response_bytes", MAX_RESPONSE_BYTES))
            payload = _validate_rule_text(text, name)
            target = rules_dir(cfg) / ("%s.yaml" % name)
            store._atomic_write(target, text, backup=False)
            log.info("规则 %s 下载成功(%s): %d 条,%.1f KB",
                     name, url.split("/")[2], len(payload), len(text) / 1024)
            return True
        except Exception as exc:
            log.warning("规则 %s 下载失败: %s", name, type(exc).__name__)
    return False


def download_all(cfg: Config) -> bool:
    """下载全部规则文件;返回是否全部成功(部分成功时下次运行会自动补)."""
    ok = True
    with store.run_lock(rules_dir(cfg) / ".subloader.lock"):
        for name in RULE_FILES:
            if not _download_one(cfg, name):
                ok = False
    return ok


def all_files_exist(cfg: Config) -> bool:
    return all((rules_dir(cfg) / ("%s.yaml" % n)).exists() for n in RULE_FILES)


def all_files_valid(cfg: Config) -> bool:
    """缓存不能仅凭存在与修改时间判定有效."""
    for name in RULE_FILES:
        try:
            _validate_rule_text((rules_dir(cfg) / (name + ".yaml")).read_text(encoding="utf-8"), name)
        except (OSError, ValueError, yaml.YAMLError):
            return False
    return True


def is_fresh(cfg: Config) -> bool:
    """全部文件存在且距上次下载未超过 refresh_days 天."""
    days = float(cfg.get("rules", "refresh_days", 7))
    limit = time.time() - days * 86400
    for name in RULE_FILES:
        p = rules_dir(cfg) / ("%s.yaml" % name)
        try:
            if not p.exists() or p.stat().st_mtime < limit:
                return False
        except OSError:
            return False
    return True


def ensure_rules(cfg: Config) -> bool:
    """确保本地规则文件可用:新鲜则跳过,过期/缺失则下载;返回是否可用."""
    valid = all_files_valid(cfg)
    if valid and is_fresh(cfg):
        log.info("本地分流规则新鲜(未超过刷新周期),跳过下载")
        return True
    log.info("分流规则缺失或已过期,开始下载(%s)", datetime.datetime.now().strftime("%H:%M:%S"))
    try:
        if download_all(cfg):
            return True
    except store.BusyError:
        log.warning("另一实例正在更新分流规则,尝试使用有效缓存")
    except OSError as exc:
        log.warning("规则目录无法更新,尝试使用有效缓存: %s", type(exc).__name__)
    log.error("规则下载失败(部分镜像可能不可达)")
    return all_files_valid(cfg)  # 仅复用经过校验的旧规则.


def providers_accessible(cfg: Config) -> bool:
    """验证发布端确实提供有效规则,不能仅凭本地缓存生成 HTTP 引用."""
    base = cfg.get("rules", "provider_base_url").rstrip("/") + "/"
    opener = _build_opener(cfg.get("rules", "tls_verify", True))
    for name in RULE_FILES:
        try:
            text = _http_get_raw(opener, base + name + ".yaml",
                                cfg.get("api", "request_timeout", 15),
                                max_bytes=cfg.get("api", "max_response_bytes", MAX_RESPONSE_BYTES))
            _validate_rule_text(text, name)
        except Exception as exc:
            log.warning("规则 HTTP 服务校验失败(%s): %s", name, type(exc).__name__)
            return False
    return True


def main() -> int:
    """独立执行:python -m core.rules"""
    from .__main__ import main as cli_main

    return cli_main(["rules", *sys.argv[1:]])


if __name__ == "__main__":
    sys.exit(main())
