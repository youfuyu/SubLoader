"""WWSS 节点 -> Clash Verge / Quantumult X 配置转换.

WWSS get-list 节点字段(实测):
  node_id, net_type(TROJAN/SHADOWSOCKS), name, server(域名), server_ip,
  server_port, method, password, protocol, obfs, load_state, bandwidth,
  quick_url(trojan://...?peer=<SNI>&allowInsecure=1#name)
"""

from __future__ import annotations

import re
import urllib.parse

from .validation import (BUILTIN_POLICIES, SS_METHODS, comment_text, host_value,
                         qx_field)

# QX 节点行格式对齐 qx-sub-converter 的 sub-resource-parser.js:
# trojan=host:port, password=PWD, over-tls=true, tls-host=SNI, tls-verification=false, tag=NAME
# shadowsocks=host:port, method=M, password=PWD, fast-open=false, udp-relay=true, tag=NAME

# 地区识别:节点名形如 "商务 · 南非ZA · 流媒体 · 台湾隧道2" / "IEPL · 深港专线 · HK0",
# 真实地区在靠前的分段;"深港IEPL/沪港IEPL/台湾隧道2"只是中转线路名,不能作为地区.
# 策略:按 "·" 分段从左到右,每段先匹配中文国名,再匹配独立两字母国家码(ZA/SP/SW 等非标码已收录).

COUNTRY_NAMES = [
    ("香港", "香港"), ("台湾", "台湾"), ("日本", "日本"), ("美国", "美国"),
    ("韩国", "韩国"), ("新加坡", "新加坡"), ("狮城", "新加坡"), ("英国", "英国"),
    ("法国", "法国"), ("德国", "德国"), ("加拿大", "加拿大"), ("澳大利亚", "澳大利亚"),
    ("南非", "南非"), ("巴西", "巴西"), ("以色列", "以色列"), ("西班牙", "西班牙"),
    ("波兰", "波兰"), ("意大利", "意大利"), ("印度", "印度"), ("土耳其", "土耳其"),
    ("荷兰", "荷兰"), ("墨西哥", "墨西哥"), ("瑞典", "瑞典"), ("俄罗斯", "俄罗斯"),
    ("马来西亚", "马来西亚"), ("泰国", "泰国"), ("菲律宾", "菲律宾"),
    ("阿根廷", "阿根廷"), ("乌克兰", "乌克兰"),
]
COUNTRY_CODES = {
    "HK": "香港", "TW": "台湾", "JP": "日本", "US": "美国", "KR": "韩国",
    "SG": "新加坡", "SP": "新加坡", "UK": "英国", "FR": "法国", "DE": "德国",
    "CA": "加拿大", "AU": "澳大利亚", "ZA": "南非", "BR": "巴西", "IL": "以色列",
    "ES": "西班牙", "PO": "波兰", "PL": "波兰", "IT": "意大利", "IN": "印度",
    "TR": "土耳其", "NL": "荷兰", "MX": "墨西哥", "SW": "瑞典", "RU": "俄罗斯",
}
# 常用地区优先;其他已识别地区按 API 首次出现顺序排列,未识别地区最后.
REGION_ORDER = ["香港", "台湾", "日本", "美国", "新加坡", "韩国",
                "英国", "法国", "德国", "加拿大", "澳大利亚"]

# 默认 YAML 分组的保留名,避免节点与代理组重名导致 Mihomo 拒绝加载.
CLASH_GROUP_NAMES = {"节点选择", "自动选择", "手动选择"} | {
    "自动选择[%s]" % code for code in ("HK", "JP", "TW", "US")}

_CODE_RE = re.compile(r"(?<![A-Z])([A-Z]{2})(?![A-Z])")


def detect_region(name: str) -> str:
    for segment in re.split(r"·", str(name)):
        segment = segment.strip()
        for keyword, region in COUNTRY_NAMES:
            if keyword in segment:
                return region
        match = _CODE_RE.search(segment)
        if match and match.group(1) in COUNTRY_CODES:
            return COUNTRY_CODES[match.group(1)]
    return "其他"


def sort_by_region(nodes: list) -> list:
    """先按地区优先级,再在同地区内直接按完整节点名称比较."""
    priority = {region: index for index, region in enumerate(REGION_ORDER)}
    first_seen = {}
    for node in nodes:
        first_seen.setdefault(node["region"], len(first_seen))
    return sorted(nodes, key=lambda node: (
        priority.get(node["region"], len(REGION_ORDER) + (node["region"] == "其他")),
        first_seen[node["region"]],
        node["name"],
    ))


class InvalidNode(Exception):
    pass


def normalize_node(raw: dict, index: int, prefer: str = "ip",
                   tls_verify: bool | None = None) -> dict:
    """把 WWSS 节点行归一化;无效节点抛 InvalidNode."""
    if not isinstance(raw, dict):
        raise InvalidNode("节点必须是对象")
    name = raw.get("name") or raw.get("name_simple") or ("node-%d" % index)
    if not qx_field(name):
        raise InvalidNode("名称包含无效字符或类型")
    name = name.strip()
    net_type = str(raw.get("net_type") or "").upper()

    host = (raw.get("server_ip") if prefer == "ip" else None) \
        or raw.get("server") or raw.get("server_ip") or ""
    try:
        host = host_value(host)
    except ValueError as exc:
        raise InvalidNode(str(exc)) from exc

    try:
        port_value = raw.get("server_port")
        if isinstance(port_value, bool) or (isinstance(port_value, float) and not port_value.is_integer()):
            raise ValueError
        port = int(port_value)
        if not (1 <= port <= 65535):
            raise ValueError
    except (TypeError, ValueError, OverflowError):
        raise InvalidNode("端口必须是 1 到 65535 之间的整数")

    password = raw.get("password")
    if not qx_field(password):
        raise InvalidNode("密码为空、类型错误或无法由 QX 无损表示")

    # 从 quick_url 提取 SNI(peer) 与 allowInsecure
    sni, allow_insecure = "", False
    quick_url = str(raw.get("quick_url") or "")
    if quick_url.startswith("trojan://"):
        try:
            parsed = urllib.parse.urlparse(quick_url)
            params = urllib.parse.parse_qs(parsed.query)
            sni = (params.get("peer") or params.get("sni") or [""])[0]
            allow_insecure = (params.get("allowInsecure") or params.get("allow_insecure") or ["0"])[0] in ("1", "true")
        except ValueError as exc:
            raise InvalidNode("quick_url 无效") from exc

    node = {
        "name": name,
        "host": host,
        "port": port,
        "password": password,
        "region": detect_region(name),
        "load_state": str(raw.get("load_state") or ""),
        "bandwidth": raw.get("bandwidth"),
    }

    if net_type == "TROJAN":
        node["type"] = "trojan"
        node["sni"] = sni
        if sni:
            try:
                node["sni"] = host_value(sni)
            except ValueError as exc:
                raise InvalidNode("SNI 无效") from exc
        node["skip_cert_verify"] = allow_insecure if tls_verify is None else not tls_verify
    elif net_type in ("SHADOWSOCKS", "SS"):
        method = raw.get("method")
        if not isinstance(method, str) or method not in SS_METHODS:
            raise InvalidNode("不支持的 ss 加密方法")
        node["type"] = "ss"
        node["method"] = method
    else:
        raise InvalidNode("不支持的节点类型")

    return node


def normalize_nodes(raw_nodes: list, prefer: str = "ip", tls_verify: bool | None = None):
    """返回 (有效节点列表, 跳过原因列表).

    末尾做重名处理:Clash 核心要求 proxy name 唯一,同名节点追加 " #N"
    (与机场官方客户端的命名习惯一致,如 "沪港IEPL #2").
    """
    valid, skipped = [], []
    for idx, raw in enumerate(raw_nodes):
        try:
            valid.append(normalize_node(raw, idx, prefer, tls_verify))
        except InvalidNode as exc:
            skipped.append("节点 #%d: %s" % (idx, exc))

    used = BUILTIN_POLICIES | CLASH_GROUP_NAMES | {"PROXY", "AUTO"}
    reserved = {n["name"] for n in valid} | used
    seen: dict = {}
    for node in valid:
        base = node["name"]
        if base in used:
            count = seen.get(base, 1) + 1
            candidate = "%s #%d" % (base, count)
            while candidate in reserved or candidate in used:
                count += 1
                candidate = "%s #%d" % (base, count)
            seen[base] = count
            node["name"] = candidate
        used.add(node["name"])

    valid = sort_by_region(valid)
    return valid, skipped


# ---------------------------------------------------------------- Clash ----

def build_clash_proxies(nodes: list) -> list:
    proxies = []
    for n in nodes:
        if n["type"] == "trojan":
            p = {
                "name": n["name"],
                "type": "trojan",
                "server": n["host"],
                "port": n["port"],
                "password": n["password"],
                "udp": True,
                "skip-cert-verify": n.get("skip_cert_verify", False),
            }
            if n.get("sni"):
                p["sni"] = n["sni"]
            proxies.append(p)
        elif n["type"] == "ss":
            proxies.append({
                "name": n["name"],
                "type": "ss",
                "server": n["host"],
                "port": n["port"],
                "cipher": n["method"],
                "password": n["password"],
                "udp": True,
            })
    return proxies


def to_clash_config(nodes: list, account: dict | None, generated_at: str) -> str:
    """生成仅含 proxies 的 Clash 节点订阅;分组和分流使用独立扩展文件."""
    import yaml

    proxies = build_clash_proxies(nodes)
    config = {"proxies": proxies}
    header_lines = [
        "# Clash 节点订阅 - SubLoader 自动生成",
        "# 生成时间: %s" % comment_text(generated_at),
        "# 节点数: %d" % len(proxies),
    ]
    if account:
        header_lines.append("# 账户: %s | 到期: %s | 流量: %s" % (
            comment_text(account.get("email", "?")),
            comment_text(account.get("vip_time_text", "?")),
            comment_text(account.get("flow_cycle_left_text", "?")),
        ))
    header = "\n".join(header_lines) + "\n\n"
    body = yaml.safe_dump(
        config, allow_unicode=True, sort_keys=False, default_flow_style=False, width=200
    )
    return header + body


# ------------------------------------------------------------------- QX ----

def build_qx_lines(nodes: list):
    """返回 [(地区, 行), ...], 行为 QX server 文件中的节点行."""
    lines = []
    for n in nodes:
        host = n["host"]
        if ":" in host and not host.startswith("["):
            host = "[%s]" % host
        if n["type"] == "trojan":
            line = "trojan=%s:%d, password=%s, over-tls=true" % (
                host, n["port"], n["password"])
            if n.get("sni"):
                line += ", tls-host=%s" % n["sni"]
            line += ", tls-verification=%s, tag=%s" % (
                "false" if n.get("skip_cert_verify", False) else "true", n["name"])
        else:
            line = "shadowsocks=%s:%d, method=%s, password=%s, fast-open=false, udp-relay=true, tag=%s" % (
                host, n["port"], n["method"], n["password"], n["name"])
        lines.append((n["region"], line))
    return lines


def to_qx_servers(nodes: list, account: dict | None, generated_at: str, group: bool = True) -> str:
    """生成 Quantumult X server(节点)文件内容."""
    out = [
        "# Quantumult X 节点文件 - SubLoader 自动生成",
        "# 生成时间: %s" % comment_text(generated_at),
        "# 节点数: %d" % len(nodes),
    ]
    if account:
        out.append("# 账户: %s | 到期: %s | 流量: %s" % (
            comment_text(account.get("email", "?")),
            comment_text(account.get("vip_time_text", "?")),
            comment_text(account.get("flow_cycle_left_text", "?")),
        ))
    out.append("")

    lines = build_qx_lines(nodes)
    if group:
        current = None
        for region, line in lines:
            if region != current:
                current = region
                out.append("# ---- %s ----" % region)
            out.append(line)
    else:
        out.extend(line for _, line in lines)
    return "\n".join(out) + "\n"
