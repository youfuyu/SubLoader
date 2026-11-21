"""Clash/QX 共用字段与可独立转换的 Clash 规则校验."""

import ipaddress
import re
import unicodedata


SS_METHODS = {
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "chacha20-ietf", "rc4-md5",
}
BUILTIN_POLICIES = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"}
INBOUND_TYPES = {
    "HTTP", "HTTPS", "SOCKS", "SOCKS4", "SOCKS5", "SHADOWSOCKS", "SNELL", "VMESS",
    "TROJAN", "REDIR", "TPROXY", "TUNNEL", "TUN", "TUIC", "HYSTERIA2", "VLESS",
    "ANYTLS", "MIERU", "INNER",
}
SIMPLE_RULES = {
    "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD", "DOMAIN-REGEX",
    "GEOIP", "SRC-GEOIP", "GEOSITE", "IP-ASN", "SRC-IP-ASN",
    "SRC-PORT", "DST-PORT", "IN-PORT", "IN-TYPE", "IN-USER", "IN-NAME",
    "PROCESS-NAME", "PROCESS-PATH", "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX",
    "NETWORK", "DSCP", "IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR",
    "RULE-SET", "MATCH",
}


def has_controls(value: str) -> bool:
    return any(unicodedata.category(c).startswith("C") or c in "\u2028\u2029" for c in value)


def comment_text(value: object) -> str:
    return "".join(" " if has_controls(c) else c for c in str(value))


def qx_field(value: object, *, empty: bool = False) -> bool:
    return (isinstance(value, str) and (empty or bool(value))
            and value == value.strip() and "," not in value and not has_controls(value))


def host_value(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("服务器地址必须是非空字符串")
    value = value.strip()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    if not qx_field(value):
        raise ValueError("服务器地址包含无效字符")
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    try:
        ascii_host = value.rstrip(".").encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("服务器域名无效") from exc
    if (len(ascii_host) > 253 or not all(
            re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", label)
            for label in ascii_host.split("."))):
        raise ValueError("服务器域名无效")
    return ascii_host


def parse_rule(rule: str) -> tuple[list[str], int]:
    """返回字段和策略位置;复杂逻辑/子规则须整组回退,不能按普通策略改写."""
    if not isinstance(rule, str) or has_controls(rule):
        raise ValueError("规则包含无效字符")
    parts = [part.strip() for part in rule.split(",")]
    if not parts or parts[0] not in SIMPLE_RULES:
        raise ValueError("不支持的规则类型")
    kind = parts[0]
    idx = len(parts) - 1
    while idx > 0 and parts[idx] in ("no-resolve", "src"):
        idx -= 1
    if idx != (1 if kind == "MATCH" else 2) or not all(parts[:idx + 1]):
        raise ValueError("规则参数数量或内容无效")
    options = parts[idx + 1:]
    if len(options) != len(set(options)) or (options and kind not in {
            "GEOIP", "SRC-GEOIP", "IP-ASN", "SRC-IP-ASN", "IP-CIDR", "IP-CIDR6",
            "SRC-IP-CIDR", "RULE-SET"}):
        raise ValueError("规则选项无效")
    if "CIDR" in kind:
        try:
            network = ipaddress.ip_network(parts[1], strict=False)
        except ValueError as exc:
            raise ValueError("规则 IP 段无效") from exc
        if kind.endswith("6") and network.version != 6:
            raise ValueError("IPv6 规则必须使用 IPv6 网段")
    elif kind in ("SRC-PORT", "DST-PORT", "IN-PORT"):
        for item in parts[1].split("/"):
            bounds = item.split("-")
            if (len(bounds) not in (1, 2) or not all(n.isascii() and n.isdecimal() and 1 <= int(n) <= 65535 for n in bounds)
                    or (len(bounds) == 2 and int(bounds[0]) > int(bounds[1]))):
                raise ValueError("规则端口范围无效")
    elif kind in ("IP-ASN", "SRC-IP-ASN", "DSCP"):
        if not parts[1].isascii() or not parts[1].isdecimal() or not 0 <= int(parts[1]) <= (63 if kind == "DSCP" else 2**32 - 1):
            raise ValueError("规则数值参数无效")
    elif kind == "IN-TYPE" and any(item.strip().upper() not in INBOUND_TYPES for item in parts[1].split("/")):
        raise ValueError("IN-TYPE 规则参数无效")
    elif kind == "NETWORK" and parts[1].lower() not in ("tcp", "udp"):
        raise ValueError("NETWORK 规则参数无效")
    elif kind.endswith("REGEX"):
        pattern = parts[1]
        if ("(?" in pattern or re.search(r"(?:[+*?]|\})\+", pattern)
                or any(m.group(1) not in r"abfnrtv\.*+?()[]{}|^$dDsSwWbBAzx0-" for m in re.finditer(r"\\(.)", pattern))
                or any(int(m.group(1)) > 1000 for m in re.finditer(r"\{([0-9]+)\}", pattern))):
            raise ValueError("复杂正则无法保证客户端兼容")
        try:
            re.compile(parts[1])
        except re.error as exc:
            raise ValueError("规则正则表达式无效") from exc
    return parts, idx
