"""带下载期限、字节上限和重定向认证保护的 urllib 传输层."""

import contextvars
import http.client
import socket
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit


_deadline = contextvars.ContextVar("subloader_http_deadline", default=None)


def remaining() -> float | None:
    deadline = _deadline.get()
    if deadline is None:
        return None
    value = deadline - time.monotonic()
    if value <= 0:
        raise TimeoutError("请求超过下载期限")
    return value


def _origin(url):
    parsed = urlsplit(url)
    return parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)


class _RedirectResponse:
    def __init__(self, response):
        self.response = response

    def __getattr__(self, name):
        return getattr(self.response, name)

    def read(self, *args):
        # urllib 默认会无上限读完中间响应体;这里直接关闭连接后跳转.
        return b""


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def http_error_302(self, req, fp, code, msg, headers):
        try:
            return super().http_error_302(req, _RedirectResponse(fp), code, msg, headers)
        finally:
            fp.close()

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        before, after = urlsplit(req.full_url), urlsplit(newurl)
        authenticated = any(key.lower() in ("x-client-token", "authorization", "proxy-authorization")
                            for key, _ in req.header_items())
        if (after.scheme not in ("http", "https") or after.username is not None
                or after.password is not None
                or (before.scheme == "https" and after.scheme != "https")
                or (authenticated and _origin(req.full_url) != _origin(newurl))):
            raise urllib.error.URLError("拒绝不安全的重定向")
        remaining()
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class _DeadlineReader:
    """响应头逐行读取也受期限约束,防止持续少量发送绕过 socket 超时."""
    def __init__(self, reader, sock):
        self.reader, self.sock = reader, sock
        self.buffer = bytearray()

    def __getattr__(self, name):
        return getattr(self.reader, name)

    def _read1(self, size):
        timeout = remaining()
        if timeout is not None:
            self.sock.settimeout(timeout)
        result = self.reader.read1(size)
        remaining()
        return result

    def read1(self, size=-1):
        remaining()
        if self.buffer:
            size = len(self.buffer) if size < 0 else min(size, len(self.buffer))
            result = bytes(self.buffer[:size])
            del self.buffer[:size]
            return result
        return self._read1(65536 if size < 0 else size)

    def read(self, size=-1):
        chunks = []
        total = 0
        while size < 0 or total < size:
            part = self.read1(65536 if size < 0 else min(65536, size - total))
            if not part:
                break
            chunks.append(part)
            total += len(part)
        return b"".join(chunks)

    def readline(self, limit=-1):
        while True:
            remaining()
            end = self.buffer.find(b"\n") + 1
            if end or (limit >= 0 and len(self.buffer) >= limit):
                end = min(end, limit) if end and limit >= 0 else end or limit
                result = bytes(self.buffer[:end])
                del self.buffer[:end]
                return result
            part = self._read1(65536 if limit < 0 else max(1, limit - len(self.buffer)))
            if not part:
                result = bytes(self.buffer)
                self.buffer.clear()
                return result
            self.buffer.extend(part)


class _Response(http.client.HTTPResponse):
    def __init__(self, sock, *args, **kwargs):
        super().__init__(sock, *args, **kwargs)
        self.fp = _DeadlineReader(self.fp, sock)


def _connect(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None):
    remaining()
    addresses = socket.getaddrinfo(address[0], address[1], 0, socket.SOCK_STREAM)
    remaining()  # 系统 DNS 解析无法由 urllib 中断;返回后立即检查期限.
    last_error = None
    for family, kind, proto, _, target in addresses:
        connection = socket.socket(family, kind, proto)
        try:
            budget = remaining()
            if budget is not None or timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                connection.settimeout(budget if budget is not None else timeout)
            if source_address:
                connection.bind(source_address)
            connection.connect(target)
            remaining()
            return connection
        except OSError as exc:
            connection.close()
            last_error = exc
    raise last_error or OSError("域名未返回可连接地址")


class _ConnectionMixin:
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._create_connection = _connect


class _HTTPConnection(_ConnectionMixin, http.client.HTTPConnection):
    response_class = _Response

    def connect(self):
        self.timeout = remaining() or self.timeout
        super().connect()
        timeout = remaining()
        if timeout is not None:
            self.sock.settimeout(timeout)


class _HTTPSConnection(_ConnectionMixin, http.client.HTTPSConnection):
    response_class = _Response

    def connect(self):
        self.timeout = remaining() or self.timeout
        http.client.HTTPConnection.connect(self)
        timeout = remaining()
        if timeout is not None:
            self.sock.settimeout(timeout)
        self.sock = self._context.wrap_socket(
            self.sock, server_hostname=self._tunnel_host or self.host)
        remaining()


class HTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        req.timeout = remaining() or req.timeout
        return self.do_open(_HTTPConnection, req)


class HTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        req.timeout = remaining() or req.timeout
        return self.do_open(_HTTPSConnection, req, context=self._context)


def read_text(opener, request, timeout, max_bytes):
    if timeout <= 0 or max_bytes < 1:
        raise ValueError("下载期限和字节上限必须为正数")
    token = _deadline.set(time.monotonic() + timeout)
    try:
        with opener.open(request, timeout=timeout) as response:
            remaining()
            if response.status != 200:
                raise ValueError("GET 请求必须返回完整的 HTTP 200 响应")
            length = response.headers.get("Content-Length")
            expected = int(length) if length is not None and not response.chunked else None
            if expected is not None and not 0 <= expected <= max_bytes:
                raise ValueError("响应体长度无效或超过大小上限")
            data = bytearray()
            while True:
                remaining()
                part = response.read1(min(65536, max_bytes + 1 - len(data)))
                remaining()
                if not part:
                    break
                data.extend(part)
                if len(data) > max_bytes:
                    raise ValueError("响应体超过大小上限")
            if expected is not None and len(data) != expected:
                raise ValueError("响应体不完整")
            return data.decode("utf-8-sig", errors="strict")
    except urllib.error.HTTPError as exc:
        exc.close()
        raise
    finally:
        _deadline.reset(token)
