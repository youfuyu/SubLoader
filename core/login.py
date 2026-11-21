#!/usr/bin/env python3
"""WWSS 登录模块（仅使用标准库，Python 3.11+）.

保持会话 → 下载人工验证码 → 验证邮箱 → 密码登录 → 保存 data.token。
按已分析的网页协议实现；站点极验需要在官方网页中完成。
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import http.cookiejar
import json
import math
import os
from pathlib import Path
import re
import ssl
import sys
import tempfile
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import warnings
import webbrowser

from .config import MAX_TOKEN_FILE_BYTES, PROJECT_ROOT


MAX_BYTES = 2 * 1024 * 1024
USER_AGENT = "Mozilla/5.0 (compatible; SubLoader login)"
DEFAULT_CONFIG = PROJECT_ROOT / "login.local.toml"


def load_login_config(path: Path | None) -> tuple[dict, Path | None]:
    """本地配置中的相对 token_file 以配置文件目录为基准."""
    selected = path.expanduser().absolute() if path is not None else DEFAULT_CONFIG
    if path is None and not selected.exists():
        return {}, None
    try:
        with selected.open("rb") as stream:
            document = tomllib.load(stream)
        settings = document.get("login")
        if set(document) != {"login"} or not isinstance(settings, dict):
            raise ValueError
        allowed = {"portal", "email", "password", "token_file", "open_captcha", "remember_days", "timeout"}
        if set(settings) - allowed:
            raise ValueError
        for key in ("portal", "email", "password", "token_file"):
            if key in settings and not isinstance(settings[key], str):
                raise ValueError
        if "open_captcha" in settings and type(settings["open_captcha"]) is not bool:
            raise ValueError
        if "remember_days" in settings and (type(settings["remember_days"]) is not int
                                             or settings["remember_days"] not in (0, 30)):
            raise ValueError
        if "timeout" in settings and (type(settings["timeout"]) not in (int, float)
                                       or not math.isfinite(settings["timeout"])
                                       or not 0 < settings["timeout"] <= 120):
            raise ValueError
        token_file = settings.get("token_file", "data/wwss-token.txt")
        if not token_file.strip():
            raise ValueError
        output = Path(token_file).expanduser()
        settings["output"] = output if output.is_absolute() else selected.parent / output
        return settings, selected
    except (OSError, ValueError):
        # TOML 解析异常包含原始行内容，不能直接回显。
        raise LoginError("登录配置不存在、无法读取或格式无效；请检查 [login] 字段及其类型") from None


class LoginError(Exception):
    """只包含可向终端输出的错误，不包含响应体、Cookie 或凭据."""


def _origin(url: str) -> tuple:
    parsed = urllib.parse.urlsplit(url)
    return parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)


class LoginRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # 密码 POST 不跟随跳转；GET 也仅允许当前 origin，避免把会话带到其他域名。
        if req.get_method() != "GET" or _origin(req.full_url) != _origin(newurl):
            raise LoginError("登录请求发生重定向；请检查门户地址或在官网完成验证")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _base64(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def decode_init(html: str) -> dict:
    """解码网页初始化数据；不执行页面中的 JavaScript、eval 或 Function."""
    try:
        match = re.search(r"\b(?:window\.)?init_text\s*=\s*'([^']+)'", html)
        if not match:
            raise ValueError
        encrypted, zero_width = match[1].split("!")
        if not zero_width or len(zero_width) % 8 or set(zero_width) - {"\u200c", "\u200d"}:
            raise ValueError
        bits = zero_width.replace("\u200c", "1").replace("\u200d", "0")
        encoded_salt = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))
        salt_script = _base64(encoded_salt.decode("ascii")).decode("utf-8")
        salt = re.search(r'\bsalt\s*:\s*"([^"\\]+)"', salt_script)[1]
        digest = hashlib.md5(salt.encode("utf-8"), usedforsecurity=False).hexdigest()
        key = base64.b64encode((digest * 25).encode("ascii"))
        cipher = _base64(encrypted)
        if len(cipher) > len(key):
            raise ValueError
        plain = bytes(((value - key[i]) ^ 7) for i, value in enumerate(cipher))
        decoded = _base64(plain.decode("ascii")).decode("utf-8")
        config = re.fullmatch(r"\s*(?:var\s+)?G\s*=\s*(\{.*\})\s*;?\s*", decoded, re.S)
        data = json.loads(config[1])
        if not isinstance(data, dict) or not isinstance(data.get("csrf_token"), str) or not data["csrf_token"]:
            raise ValueError
        return data
    except (ValueError, TypeError, IndexError, UnicodeError, AttributeError):
        raise LoginError("无法解析网页登录初始化数据；页面协议可能已变化或触发了站点验证") from None


def page_options(html: str) -> str:
    config = re.search(r"\b(?:window\.)?page_config\s*=\s*\{(.*?)\}\s*;", html, re.S)
    if not config:
        raise LoginError("未找到网页登录配置；请确认门户地址")
    enabled = re.search(r"\bgt_enabled\s*:\s*(true|false)\b", config[1])
    if not enabled:
        raise LoginError("未识别页面的验证码配置")
    if enabled[1] == "true":
        raise LoginError("站点已开启极验，请在官方网页登录完成验证；此脚本仅支持人工图片验证码")
    device = re.search(r'''\bdevice_id\s*:\s*(["'])([^"'\\\r\n]*)\1''', config[1])
    if not device:
        raise LoginError("未识别页面的设备 ID 配置")
    return device[2]


class LoginClient:
    def __init__(self, portal: str, timeout: float = 20):
        try:
            parsed = urllib.parse.urlsplit(portal)
            loopback = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
            if (not parsed.hostname or parsed.username is not None or parsed.password is not None
                    or parsed.path not in {"", "/"} or parsed.query or parsed.fragment
                    or (parsed.scheme != "https" and not (parsed.scheme == "http" and loopback))):
                raise ValueError
            _origin(portal)  # 同时校验端口。
        except ValueError:
            raise LoginError("--portal 必须是 HTTPS 门户根地址，不含路径、参数或凭据") from None
        if not math.isfinite(timeout) or not 0 < timeout <= 120:
            raise LoginError("--timeout 必须大于 0 且不超过 120 秒")
        self.portal = portal.rstrip("/")
        self.timeout = timeout
        self.device_id = ""
        self.csrf_token = ""
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
            urllib.request.HTTPCookieProcessor(self.cookies), LoginRedirectHandler(),
        )

    def request(self, path: str, fields: dict | None = None) -> bytes:
        headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
        body = None
        if fields is not None:
            body = urllib.parse.urlencode(fields).encode("utf-8")
            headers.update({
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "X-Requested-With": "XMLHttpRequest", "Origin": self.portal,
                "Referer": self.portal + "/portal/account/login?protocol=westworldss",
            })
        req = urllib.request.Request(self.portal + path, data=body, headers=headers)
        try:
            with self.opener.open(req, timeout=self.timeout) as response:
                payload = response.read(MAX_BYTES + 1)
                if len(payload) > MAX_BYTES:
                    raise LoginError("登录响应超过大小限制")
                return payload
        except urllib.error.HTTPError as exc:
            status = exc.code
            exc.close()
            raise LoginError("登录服务返回 HTTP %d，请检查门户地址或官网验证提示" % status) from None
        except (urllib.error.URLError, OSError, ValueError):
            raise LoginError("登录网络请求失败，请检查网络、证书和门户地址") from None

    def post(self, path: str, fields: dict) -> dict:
        try:
            payload = json.loads(self.request(path, fields).decode("utf-8"))
        except (ValueError, UnicodeError):
            raise LoginError("登录服务未返回有效 JSON，可能需要在官网完成验证") from None
        if not isinstance(payload, dict) or type(payload.get("code")) is not int:
            raise LoginError("登录接口响应格式无效")
        if payload["code"] != 0:
            # 服务端 message 可能回显凭据，因此只显示数字状态码。
            raise LoginError("登录接口业务失败（code=%d），请检查验证码、密码或官网提示" % payload["code"])
        if not isinstance(payload.get("data"), dict):
            raise LoginError("登录接口缺少有效 data 对象")
        return payload["data"]

    def prepare(self) -> bytes:
        try:
            html = self.request("/portal/account/login?protocol=westworldss").decode("utf-8")
        except UnicodeError:
            raise LoginError("登录页编码无效") from None
        self.device_id = page_options(html)
        self.csrf_token = decode_init(html)["csrf_token"]
        return self.request("/portal/account/get-verify-image")

    def check_email(self, email: str, verify_code: str) -> None:
        if not self.csrf_token:
            raise LoginError("请先初始化登录会话")
        data = self.post("/user/account/check-is-registed", {
            "email": email.strip(), "csrf_token": self.csrf_token, "verify_code": verify_code.strip(),
        })
        if data.get("is_registed") is not True:
            raise LoginError("接口未确认邮箱已注册，未尝试注册或密码登录")

    def login(self, email: str, password: str, remember_days: int = 30) -> str:
        data = self.post("/user/account/login", {
            "email": email.strip(), "password": password.strip(),
            "auto_login_days": remember_days, "device_id": self.device_id,
        })
        token = data.get("token")
        if (not isinstance(token, str) or not token or len(token) >= MAX_TOKEN_FILE_BYTES
                or any(ord(c) < 33 or ord(c) > 126 for c in token)):
            raise LoginError("登录成功响应中未包含有效 token")
        return token


def save_token(path: Path, token: str) -> None:
    """原子替换文件；新文件权限为 0600，失败时保留原 token."""
    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".wwss-token-", delete=False) as stream:
            temporary = Path(stream.name)
            os.chmod(temporary, 0o600)
            stream.write(token + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def captcha_extension(data: bytes) -> str:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if data.startswith(b"\xff\xd8\xff"):
        return ".jpg"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return ".gif"
    if data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return ".webp"
    raise LoginError("验证码接口未返回受支持的图片，可能触发了站点验证")


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-c", "--config", type=Path, default=argparse.SUPPRESS,
                        help="本地登录配置（默认 项目根/login.local.toml）")
    parser.add_argument("--portal", help="覆盖配置中的 HTTPS 门户根地址")
    parser.add_argument("--email", help="登录邮箱；也可用 SUBLOADER_EMAIL 或交互输入")
    parser.add_argument("--output", type=Path, help="覆盖配置中的 token_file，相对路径以调用目录为基准")
    parser.add_argument("--open-captcha", action=argparse.BooleanOptionalAction, default=None,
                        help="用默认浏览器打开本地验证码图片")
    parser.add_argument("--remember-days", type=int, choices=(0, 30))
    parser.add_argument("--timeout", type=float, help="网络操作超时秒数，最大 120")


def run(args: argparse.Namespace) -> int:
    try:
        config = getattr(args, "config", None)
        settings, config_path = load_login_config(Path(config) if config is not None else None)
        portal = args.portal if args.portal is not None else settings.get("portal", "")
        if not portal:
            raise LoginError("请在 login.local.toml 的 [login] 中填写 portal，或使用 --portal")
        timeout = args.timeout if args.timeout is not None else settings.get("timeout", 20)
        remember_days = args.remember_days if args.remember_days is not None else settings.get("remember_days", 30)
        open_captcha = args.open_captcha if args.open_captcha is not None else settings.get("open_captcha", False)
        output = args.output if args.output is not None else settings.get("output", PROJECT_ROOT / "data/wwss-token.txt")
        output = output.expanduser()
        if config_path is not None and (output.resolve() == config_path.resolve()
                or (output.exists() and os.path.samefile(output, config_path))):
            raise LoginError("token_file 不能指向登录配置文件")
        client = LoginClient(portal, timeout)
        email = args.email if args.email is not None else os.environ.get("SUBLOADER_EMAIL", settings.get("email", ""))
        if not email and "SUBLOADER_EMAIL" not in os.environ and args.email is None:
            email = input("登录邮箱：")
        email = email.strip()
        if not email or "@" not in email:
            raise LoginError("请输入有效邮箱")
        password = os.environ.get("SUBLOADER_PASSWORD", settings.get("password") or None)
        if password is not None and not password.strip():
            raise LoginError("密码不能为空")
        image = client.prepare()
        extension = captcha_extension(image)
        with tempfile.TemporaryDirectory(prefix="wwss-captcha-") as directory:
            image_path = Path(directory) / ("captcha" + extension)
            image_path.write_bytes(image)
            os.chmod(image_path, 0o600)
            print("验证码图片：%s" % image_path)
            if open_captcha:
                webbrowser.open(image_path.as_uri())
            verify_code = input("输入图片验证码：").strip()
            if not verify_code:
                raise LoginError("验证码不能为空")
            client.check_email(email, verify_code)
            if password is None:
                with warnings.catch_warnings():
                    warnings.simplefilter("error", getpass.GetPassWarning)
                    password = getpass.getpass("登录密码（不回显）：")
            if not password.strip():
                raise LoginError("密码不能为空")
            token = client.login(email, password, remember_days)
            save_token(output, token)
        print("登录成功，token 已保存至 %s（权限 0600）" % output)
        return 0
    except LoginError as exc:
        print("登录失败：%s" % exc, file=sys.stderr)
    except getpass.GetPassWarning:
        print("当前终端不支持隐藏密码；请使用交互终端或 SUBLOADER_PASSWORD 环境变量", file=sys.stderr)
    except (EOFError, KeyboardInterrupt):
        print("已取消登录", file=sys.stderr)
    except OSError:
        print("无法读写登录所需文件；原 token 文件未被部分覆盖", file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    add_arguments(parser)
    return run(parser.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
