"""WWSS(西部世界VPN/William加速器)订阅 API 客户端.

接口约定(逆向 WestWorldSS 2.0.4 得出):
  GET {api}/user/node/get-list      节点列表
  GET {api}/user/account/get-info   账户信息(到期/流量)
  GET {cloud}/speed/cloudapi        域名发现 {"data":{"api_urls":[...],"cloud_urls":[...]}}
请求头: X-Client-Token: <token>, Content-type: application/json
"""

from __future__ import annotations

import json
import logging
import os
import plistlib
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from .config import MAX_RESPONSE_BYTES, MAX_TOKEN_FILE_BYTES, is_http_url
from . import http_transport

log = logging.getLogger("core.fetch")

WWSS_PLIST = Path("~/Library/Preferences/com.wwss.WWSS.plist").expanduser()
USER_AGENT = "WestWorldSS/2.0.4 (Macintosh; macOS SubLoader)"


def _url_host(url: str) -> str:
    """日志只记录域名,不输出订阅路径中的凭据."""
    return urlsplit(url).hostname or "unknown"


def read_token_from_wwss() -> str | None:
    """从 西部世界VPN.app 的偏好设置读取登录 token."""
    try:
        with open(WWSS_PLIST, "rb") as fh:
            data = plistlib.load(fh)
        token = data.get("token")
        if isinstance(token, str) and token:
            return token
    except FileNotFoundError:
        log.warning("未找到 %s(西部世界VPN 可能未安装或未登录)", WWSS_PLIST)
    except Exception as exc:  # plistlib 异常等
        log.warning("读取 %s 失败: %s", WWSS_PLIST, exc)
    return None


def read_token_from_file(path: Path) -> str:
    """读取单行 token；显式配置的文件失败时不回退其他账户."""
    try:
        if not path.is_file():
            raise ValueError
        with path.open("rb") as stream:
            raw = stream.read(MAX_TOKEN_FILE_BYTES + 1)
        if len(raw) > MAX_TOKEN_FILE_BYTES:
            raise ValueError
        token = raw.decode("utf-8").removesuffix("\n").removesuffix("\r")
        if not token or any(ord(c) < 33 or ord(c) > 126 for c in token):
            raise ValueError
        return token
    except (OSError, ValueError):
        raise RuntimeError("token 文件不存在、不可读取或不是有效的单行 token；请运行 ./run.sh login 重新生成") from None


def resolve_token(cfg) -> str | None:
    token = cfg.get("api", "token", "auto")
    if token and token != "auto":
        return token
    if cfg.token_file is not None:
        return read_token_from_file(cfg.token_file)
    return read_token_from_wwss()


def _build_opener(tls_verify: bool):
    ctx = ssl.create_default_context()
    if not tls_verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    handler = http_transport.HTTPSHandler(context=ctx)
    # 显式禁用环境代理(HTTP_PROXY 等),对齐本机直连网络
    return urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                      http_transport.HTTPHandler(), handler,
                                      http_transport.SafeRedirectHandler())


def _http_get_raw(opener, url: str, timeout: float, headers: dict | None = None,
                  max_bytes: int = MAX_RESPONSE_BYTES) -> str:
    """GET 返回原始文本."""
    base = {"User-Agent": USER_AGENT}
    if headers:
        base.update(headers)
    req = urllib.request.Request(url, headers=base, method="GET")
    return http_transport.read_text(opener, req, timeout, max_bytes)


def _http_get(opener, url: str, token: str | None, timeout: float,
              max_bytes: int = MAX_RESPONSE_BYTES) -> dict:
    """GET 并解析 JSON;非 200 或 JSON 异常直接抛错."""
    headers = {"Content-type": "application/json", "Accept": "application/json"}
    if token:
        headers["X-Client-Token"] = token
    return json.loads(_http_get_raw(opener, url, timeout, headers, max_bytes))


def fetch_subscription_text(cfg) -> str | None:
    """抓取订阅链接原文(用于提取 clash 分流规则);失败返回 None,不中断主流程."""
    url = cfg.get("api", "subscription_url", "")
    if not url:
        return None
    opener = _build_opener(bool(cfg.get("api", "tls_verify", False)))
    try:
        text = _http_get_raw(opener, url, float(cfg.get("api", "request_timeout", 15)),
                             max_bytes=cfg.get("api", "max_response_bytes", MAX_RESPONSE_BYTES))
        log.info("订阅链接抓取成功(%s),%d 字节", _url_host(url), len(text.encode("utf-8")))
        return text
    except Exception as exc:
        log.warning("订阅链接 %s 抓取失败(将回退内置规则): %s", _url_host(url), type(exc).__name__)
        return None


def discover_api_urls(cfg, opener) -> list[str]:
    """请求 cloudapi 拿最新 API 域名;失败返回空列表(调用方回退配置里的 api_urls)."""
    discovered: list[str] = []
    for cloud_url in cfg.get("api", "cloudapi_urls", []):
        try:
            payload = _http_get(opener, cloud_url, None, cfg.get("api", "request_timeout", 15),
                                cfg.get("api", "max_response_bytes", MAX_RESPONSE_BYTES))
            urls = (payload.get("data") or {}).get("api_urls") or []
            if isinstance(urls, list) and urls:
                discovered = list(dict.fromkeys(
                    u.rstrip("/") for u in urls
                    if is_http_url(u) and urlsplit(u).scheme == "https"
                    and not urlsplit(u).query))
                if discovered:
                    log.info("cloudapi 域名发现成功(%s): %s", _url_host(cloud_url),
                             ", ".join(_url_host(u) for u in discovered))
                    break
            log.warning("cloudapi %s 返回无有效 api_urls", _url_host(cloud_url))
        except Exception as exc:
            log.warning("cloudapi %s 请求失败: %s", _url_host(cloud_url), type(exc).__name__)
    return discovered


def _validate_payload(path: str, payload: object) -> None:
    if not isinstance(payload, dict) or type(payload.get("code")) is not int or payload["code"] != 0:
        raise ValueError("API 响应格式或业务状态无效")
    if path == "/user/node/get-list":
        from .converter import normalize_nodes

        nodes, _ = normalize_nodes(extract_nodes(payload))
        if not nodes:
            raise ValueError("API 响应中没有有效节点")
    elif path == "/user/account/get-info" and not isinstance(payload.get("data"), dict):
        raise ValueError("账户信息格式无效")


def _try_urls(cfg, opener, path: str, token: str) -> tuple[str, dict]:
    """按顺序尝试各 API 域名;全部失败抛最后一个异常."""
    urls = list(cfg.get("api", "api_urls", []))
    timeout = float(cfg.get("api", "request_timeout", 15))
    retry = int(cfg.get("api", "retry_per_url", 1))
    last_exc: Exception | None = None
    for base in urls:
        for attempt in range(retry + 1):
            try:
                payload = _http_get(opener, base.rstrip("/") + path, token, timeout,
                                    cfg.get("api", "max_response_bytes", MAX_RESPONSE_BYTES))
                _validate_payload(path, payload)
                return base, payload
            except urllib.error.HTTPError as exc:
                last_exc = exc
                log.warning("HTTP %s: %s%s (第 %d 次)", exc.code, _url_host(base), path, attempt + 1)
            except Exception as exc:
                last_exc = exc
                log.warning("请求失败: %s%s: %s (第 %d 次)", _url_host(base), path, type(exc).__name__, attempt + 1)
            if attempt < retry:
                time.sleep(2)
    raise RuntimeError("所有 API 域名均失败,最后错误类型: %s" % type(last_exc).__name__)


def fetch(cfg) -> dict:
    """完整抓取流程:域名发现 → 节点列表(→ 账户信息).返回结果 dict."""
    opener = _build_opener(bool(cfg.get("api", "tls_verify", False)))

    token = resolve_token(cfg)
    if not token:
        raise RuntimeError(
            "无法获得 token:请配置 [api] token_file 并运行 ./run.sh login，"
            "或填写 token，或保持 auto 并确保 西部世界VPN.app 已登录"
        )
    if cfg.get("api", "token", "auto") not in ("", "auto"):
        token_source = "环境变量" if "SUBLOADER_TOKEN" in os.environ else "本机配置"
    else:
        token_source = "token 文件" if cfg.token_file is not None else "WWSS 偏好设置(auto)"
    log.info("token 来源: %s", token_source)

    # 域名发现:成功则把发现结果插到配置列表前面
    discovered = discover_api_urls(cfg, opener)
    if discovered:
        merged = discovered + [u for u in cfg.get("api", "api_urls", []) if u not in discovered]
        cfg["api"]["api_urls"] = merged

    base, payload = _try_urls(cfg, opener, "/user/node/get-list", token)
    log.info("get-list 成功(%s),原始响应 %d 字节", _url_host(base), len(json.dumps(payload)))

    # get-info 直接优先用刚成功的域名,避免重新按序摸索
    cfg["api"]["api_urls"] = [base] + [u for u in cfg.get("api", "api_urls", []) if u != base]

    result = {
        "api_base": base,
        "nodes_payload": payload,
        "account": None,
        "fetched_at": time.time(),
    }

    if cfg.get("api", "fetch_account_info", True):
        try:
            _, info = _try_urls(cfg, opener, "/user/account/get-info", token)
            if info.get("code") == 0:
                result["account"] = info.get("data") or {}
                log.info("账户信息读取成功")
        except Exception as exc:
            log.warning("get-info 失败(不影响节点输出): %s", type(exc).__name__)

    return result


def extract_nodes(nodes_payload: dict) -> list[dict]:
    """从 get-list 响应中提取节点列表,兼容 data 为 list 或 dict 包 list 的形态."""
    if not isinstance(nodes_payload, dict):
        return []
    data = nodes_payload.get("data")
    if isinstance(data, list):
        return [n for n in data if isinstance(n, dict)]
    if isinstance(data, dict):
        for key in ("rows", "list", "node_list", "nodes", "server_list"):
            if isinstance(data.get(key), list):
                return [n for n in data[key] if isinstance(n, dict)]
        # data 本身可能就是单个节点?不是列表就当作无法解析
    return []
