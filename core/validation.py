"""Clash/QX 节点共用字段校验."""

import ipaddress
import re
import unicodedata


SS_METHODS = {
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "chacha20-ietf", "rc4-md5",
}
# 内核内置策略及自动创建的 GLOBAL 组,节点不能占用这些名称.
BUILTIN_POLICIES = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "PASS-RULE", "COMPATIBLE", "GLOBAL"}


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
