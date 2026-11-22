"""单次执行流程:抓取 -> 校验 -> 转换 -> 覆盖目标文件."""

from __future__ import annotations

import datetime
import logging

import yaml

from . import converter, fetcher, store
from .validation import BUILTIN_POLICIES, SS_METHODS, host_value, qx_field

log = logging.getLogger("core.run")


def _validate_outputs(clash_text: str, qx_text: str, expected_count: int) -> None:
    config = yaml.safe_load(clash_text)
    if not isinstance(config, dict) or not isinstance(config.get("proxies"), list):
        raise ValueError("Clash proxies 格式无效")
    if set(config) != {"proxies"}:
        raise ValueError("Clash 节点订阅只允许包含 proxies;分组和分流由独立扩展维护")
    proxies = config["proxies"]
    if expected_count < 1 or len(proxies) != expected_count or any(not isinstance(p, dict) for p in proxies):
        raise ValueError("Clash 节点数量或条目类型无效")
    names = [p.get("name") for p in proxies]
    if (any(not qx_field(n) for n in names)
            or len(set(names)) != expected_count or set(names) & BUILTIN_POLICIES):
        raise ValueError("Clash 节点数量或名称唯一性自检失败")
    for proxy in proxies:
        host_value(proxy.get("server"))
        if (type(proxy.get("port")) is not int or not 1 <= proxy["port"] <= 65535
                or not qx_field(proxy.get("password"))):
            raise ValueError("Clash 节点地址、端口或密码无效")
        if proxy.get("type") == "ss":
            if not isinstance(proxy.get("cipher"), str) or proxy["cipher"] not in SS_METHODS:
                raise ValueError("Clash SS 加密方法无效")
        elif proxy.get("type") == "trojan":
            if type(proxy.get("skip-cert-verify")) is not bool:
                raise ValueError("Clash TLS 设置无效")
            if proxy.get("sni"):
                host_value(proxy["sni"])
        else:
            raise ValueError("Clash 节点类型无效")
    content = [line for line in qx_text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    lines = [line for line in content if line.startswith(("trojan=", "shadowsocks="))]
    if len(lines) != expected_count or len(content) != expected_count:
        raise ValueError("QX 节点数量自检失败")
    tags = [line.rsplit(", tag=", 1)[-1] for line in lines]
    if tags != names:
        raise ValueError("Clash 与 QX 节点名称不一致")
    for proxy, line in zip(proxies, lines):
        parts = line.split(",")
        kind, endpoint = parts[0].split("=", 1)
        try:
            host, port = endpoint.rsplit(":", 1)
            fields = {}
            for part in parts[1:]:
                key, value = part.strip().split("=", 1)
                if key in fields or not qx_field(value):
                    raise ValueError
                fields[key] = value
            if (host_value(host) != host_value(proxy["server"]) or not port.isascii()
                    or not port.isdecimal() or int(port) != proxy["port"]
                    or fields.get("password") != proxy["password"] or fields.get("tag") != proxy["name"]):
                raise ValueError
            if proxy["type"] == "trojan":
                allowed = {"password", "tag", "over-tls", "tls-verification", "tls-host"}
                if (kind != "trojan" or fields.get("over-tls") != "true"
                        or fields.get("tls-host", "") != proxy.get("sni", "")
                        or fields.get("tls-verification") != str(not proxy["skip-cert-verify"]).lower()):
                    raise ValueError
            else:
                allowed = {"password", "tag", "method", "fast-open", "udp-relay"}
                if (kind != "shadowsocks" or fields.get("method") != proxy["cipher"]
                        or fields.get("fast-open") != "false" or fields.get("udp-relay") != "true"):
                    raise ValueError
            if set(fields) - allowed:
                raise ValueError
        except (ValueError, KeyError) as exc:
            raise ValueError("Clash 与 QX 节点参数不一致或 QX 字段无效") from exc


def run_once(cfg) -> bool:
    """执行一次完整流程.下载成功且转换结果有效才覆盖目标文件;否则保持原文件不变.

    返回 True 表示成功.
    """
    generated_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 1. 抓取(域名发现 + get-list + get-info)
    result = fetcher.fetch(cfg)
    payload = result["nodes_payload"]
    account = result.get("account")

    # 2. 提取并校验节点
    raw_nodes = fetcher.extract_nodes(payload)
    if not raw_nodes:
        log.error("get-list 响应中没有节点(data.rows 为空),不覆盖目标文件")
        return False
    log.info("API 返回 %d 个节点", len(raw_nodes))

    nodes, skipped = converter.normalize_nodes(
        raw_nodes, tls_verify=cfg.get("output", "tls_verify", False))
    for reason in skipped:
        log.warning("跳过无效节点: %s", reason)
    if not nodes:
        log.error("所有节点均无效,不覆盖目标文件")
        return False
    log.info("有效节点 %d 个(跳过 %d 个)", len(nodes), len(skipped))

    # 3. 仅转换节点;分组和分流由 Clash Verge 的独立扩展处理.
    metadata = account if cfg.get("output", "include_account_info", False) else None
    clash_text = converter.to_clash_config(nodes, metadata, generated_at)
    qx_text = converter.to_qx_servers(
        nodes, metadata, generated_at,
        group=bool(cfg.get("output", "include_quantumultx_group", True)),
    )

    # 4. 自检通过前不写入原始 JSON 或订阅文件.
    try:
        _validate_outputs(clash_text, qx_text, len(nodes))
    except Exception as exc:
        log.error("转换结果自检失败,不覆盖目标文件: %s", type(exc).__name__)
        return False
    log.info("自检通过:clash proxies=%d,qx 节点行=%d", len(nodes), len(nodes))

    # 5. 一起提交原始 JSON 和两种订阅;写入异常时回滚.
    store.save_bundle(cfg, payload, account, clash_text, qx_text)
    log.info("执行成功:已更新 %s 与 %s", cfg.clash_path.name, cfg.quantumultx_path.name)
    return True


def run_with_retry(cfg, attempts: int | None = None) -> bool:
    """带重试的执行:失败后间隔 retry_interval_minutes 再试,最多 max_attempts 次.

    attempts 显式指定时可覆盖配置(如 --once 传 1).
    """
    import time as _time

    max_attempts = attempts if attempts is not None else int(
        cfg.get("schedule", "max_attempts", 3))
    interval = float(cfg.get("schedule", "retry_interval_minutes", 5.0))

    for attempt in range(1, max_attempts + 1):
        log.info("第 %d/%d 次尝试", attempt, max_attempts)
        try:
            if run_once(cfg):
                return True
        except Exception:
            log.exception("第 %d 次尝试异常", attempt)
        if attempt < max_attempts:
            wait = interval * 60
            log.warning("执行失败,%.0f 秒后重试(剩余 %d 次)", wait, max_attempts - attempt)
            _time.sleep(wait)
    log.error("已达最大尝试次数 %d,本次执行失败,请检查上方错误日志", max_attempts)
    return False
