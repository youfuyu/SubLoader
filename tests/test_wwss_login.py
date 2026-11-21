"""登录协议集成测试：合成页面与本机 HTTP 服务，不使用真实账号."""

import base64
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock
from urllib.parse import parse_qs

from core import login
from core import __main__ as cli, fetcher
from core.config import Config, DEFAULTS


def write_config(path, **settings):
    path.write_text("[login]\n" + "\n".join(
        "%s = %s" % (key, json.dumps(value, ensure_ascii=False)) for key, value in settings.items()))


def login_page(gt=False):
    # 构造官方 DD 格式的网页配置，而非执行来自页面的代码。
    config = json.dumps({"csrf_token": "test-csrf", "ROOT_URL": "https://example.invalid/"})
    salt = "test-salt"
    key = base64.b64encode((hashlib.md5(salt.encode()).hexdigest() * 25).encode())
    plain = base64.b64encode(("G=" + config).encode())
    cipher = base64.b64encode(bytes((value ^ 7) + key[i] for i, value in enumerate(plain))).decode()
    salt_script = base64.b64encode(('G={salt:"' + salt + '"}').encode())
    zero_width = "".join("\u200c" if bit == "1" else "\u200d"
                         for byte in salt_script for bit in format(byte, "08b"))
    return ("<script>window.page_config = {gt_enabled: %s, device_id: 'test-device'};</script>"
            "<script>window.init_text = '%s!%s';</script>" % (str(gt).lower(), cipher, zero_width))


class TestLoginFlow(unittest.TestCase):
    def setUp(self):
        self.state = {"requests": [], "registered": True, "token": "test-token", "gt": False,
                      "redirect": False, "failure": None}
        state = self.state

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def send(self, body, content_type="application/json", status=200, headers=()):
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                for name, value in headers:
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                state["requests"].append((self.path, {}, dict(self.headers)))
                if self.path.startswith("/portal/account/login?"):
                    self.send(login_page(state["gt"]).encode(), "text/html", headers=[
                        ("Set-Cookie", "test_session=session-id; Path=/; HttpOnly")])
                elif self.path == "/portal/account/get-verify-image":
                    self.send(b"\x89PNG\r\n\x1a\nsynthetic-image", "image/png")
                elif self.path == "/user/node/get-list" and self.headers.get("X-Client-Token") == state["token"]:
                    self.send(json.dumps({"code": 0, "data": [{
                        "name": "test-node", "server": "node.example.invalid", "server_port": 443,
                        "net_type": "TROJAN", "password": "node-password",
                    }]}).encode())
                else:
                    self.send(b"{}", status=404)

            def do_POST(self):
                fields = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode(),
                                  keep_blank_values=True)
                state["requests"].append((self.path, fields, dict(self.headers)))
                if "test_session=session-id" not in self.headers.get("Cookie", ""):
                    self.send(b'{"code":1,"data":{}}')
                elif state["redirect"]:
                    self.send(b"", status=302, headers=[("Location", "https://example.invalid/leak")])
                elif state["failure"] is not None:
                    self.send(json.dumps(state["failure"]).encode())
                elif self.path == "/user/account/check-is-registed":
                    self.send(json.dumps({"code": 0, "data": {"is_registed": state["registered"]}}).encode())
                elif self.path == "/user/account/login":
                    self.send(json.dumps({"code": 0, "data": {"token": state["token"]}}).encode())
                else:
                    self.send(b"{}", status=404)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.close_server)
        self.portal = "http://127.0.0.1:%d" % self.server.server_port

    def close_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def test_full_cli_flow_cookies_encoding_and_private_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "token.txt"
            stdout, stderr = io.StringIO(), io.StringIO()
            with mock.patch.dict(os.environ, {"SUBLOADER_PASSWORD": "  p+a&=中文  "}), \
                    mock.patch("builtins.input", return_value="abcd"), \
                    mock.patch.object(login.webbrowser, "open") as open_image, \
                    contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = login.main(["--portal", self.portal, "--email", "user@example.invalid",
                                   "--output", str(output), "--open-captcha"])
            self.assertEqual(code, 0, stderr.getvalue())
            self.assertEqual(output.read_text(), "test-token\n")
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertNotIn("test-token", stdout.getvalue() + stderr.getvalue())
            self.assertNotIn("p+a&", stdout.getvalue() + stderr.getvalue())
            image_uri = open_image.call_args.args[0]
            self.assertTrue(image_uri.endswith(".png"))
            self.assertFalse(Path(image_uri.removeprefix("file://")).exists())
        requests = self.state["requests"]
        self.assertEqual(len(requests), 4)
        self.assertIn("test_session=session-id", requests[1][2]["Cookie"])
        self.assertEqual(requests[2][1], {"email": ["user@example.invalid"],
                                        "csrf_token": ["test-csrf"], "verify_code": ["abcd"]})
        self.assertEqual(requests[3][1], {"email": ["user@example.invalid"],
                                        "password": ["p+a&=中文"], "auto_login_days": ["30"],
                                        "device_id": ["test-device"]})
        self.assertTrue(requests[3][2]["Content-Type"].startswith("application/x-www-form-urlencoded"))

    def test_unknown_account_does_not_register_or_submit_password(self):
        self.state["registered"] = False
        client = login.LoginClient(self.portal)
        client.prepare()
        with self.assertRaisesRegex(login.LoginError, "未确认邮箱已注册"):
            client.check_email("user@example.invalid", "abcd")
        self.assertEqual(len(self.state["requests"]), 3)

    def test_local_config_credentials_output_and_options(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "login.local.toml"
            write_config(config, portal=self.portal, email="user@example.invalid", password="test-password",
                         token_file="nested/token.txt", open_captcha=True, remember_days=0)
            environment = {k: v for k, v in os.environ.items()
                           if k not in {"SUBLOADER_EMAIL", "SUBLOADER_PASSWORD"}}
            with mock.patch.dict(os.environ, environment, clear=True), \
                    mock.patch("builtins.input", return_value="abcd") as input_mock, \
                    mock.patch.object(login.getpass, "getpass") as getpass_mock, \
                    mock.patch.object(login.webbrowser, "open") as open_image, \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(login.main(["-c", str(config)]), 0)
            self.assertEqual((Path(directory) / "nested/token.txt").read_text(), "test-token\n")
            input_mock.assert_called_once_with("输入图片验证码：")
            getpass_mock.assert_not_called()
            open_image.assert_called_once()
            self.assertEqual(self.state["requests"][-1][1]["auto_login_days"], ["0"])
            self.assertEqual(self.state["requests"][-1][1]["password"], ["test-password"])

    def test_launcher_login_from_other_directory_with_relative_config(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_config(root / "custom.local.toml", portal=self.portal, email="user@example.invalid",
                         password="test-password", token_file="out/token.txt", open_captcha=False)
            # 不在启动器集成测试中访问依赖索引。
            uv = root / "uv"
            uv.write_text("#!/bin/sh\nexit 0\n")
            uv.chmod(0o755)
            environment = {k: v for k, v in os.environ.items()
                           if k not in {"SUBLOADER_EMAIL", "SUBLOADER_PASSWORD", "PYTHONPATH"}}
            environment["PATH"] = str(root) + os.pathsep + environment.get("PATH", "")
            result = subprocess.run([str(login.PROJECT_ROOT / "run.sh"), "login", "-c", "custom.local.toml"],
                                    cwd=root, env=environment, input="abcd\n", capture_output=True,
                                    text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((root / "out/token.txt").read_text(), "test-token\n")
            self.assertNotIn("test-token", result.stdout + result.stderr)

    def test_core_login_token_file_is_used_by_node_fetch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            login_config = root / "login.local.toml"
            write_config(login_config, portal=self.portal, email="user@example.invalid",
                         password="test-password", token_file="private/token.txt", open_captcha=False)
            environment = {k: v for k, v in os.environ.items()
                           if k not in {"SUBLOADER_EMAIL", "SUBLOADER_PASSWORD"}}
            with mock.patch.dict(os.environ, environment, clear=True), \
                    mock.patch("builtins.input", return_value="abcd"), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(["login", "-c", str(login_config)]), 0)
            settings = copy.deepcopy(DEFAULTS)
            settings["api"].update(token="auto", token_file=str(root / "private/token.txt"),
                                   api_urls=[self.portal], cloudapi_urls=[], fetch_account_info=False)
            cfg = Config(settings, root / "config.toml")
            self.assertEqual(cfg.validate(), [])
            with mock.patch.object(fetcher, "read_token_from_wwss") as read_app, \
                    self.assertLogs("core.fetch", level="INFO") as logs:
                result = fetcher.fetch(cfg)
            self.assertEqual(result["nodes_payload"]["data"][0]["name"], "test-node")
            self.assertEqual(self.state["requests"][-1][2]["X-Client-Token"], "test-token")
            self.assertIn("token 文件", "\n".join(logs.output))
            self.assertNotIn("test-token", "\n".join(logs.output))
            read_app.assert_not_called()

    def test_geetest_stops_before_sending_account_data(self):
        self.state["gt"] = True
        with self.assertRaisesRegex(login.LoginError, "极验"):
            login.LoginClient(self.portal).prepare()
        self.assertEqual(len(self.state["requests"]), 1)

    def test_server_error_does_not_echo_response_secrets(self):
        self.state["failure"] = {"code": 123, "message": "reflected-password", "data": {}}
        client = login.LoginClient(self.portal)
        client.prepare()
        with self.assertRaises(login.LoginError) as error:
            client.login("user@example.invalid", "reflected-password")
        self.assertIn("123", str(error.exception))
        self.assertNotIn("reflected-password", str(error.exception))

    def test_password_redirect_is_not_followed(self):
        self.state["redirect"] = True
        client = login.LoginClient(self.portal)
        client.prepare()
        with self.assertRaisesRegex(login.LoginError, "重定向"):
            client.login("user@example.invalid", "test-password")
        self.assertEqual(len(self.state["requests"]), 3)

    def test_invalid_tokens_are_rejected(self):
        client = login.LoginClient(self.portal)
        client.prepare()
        for token in (None, 123, "", "bad\r\nheader", " padded "):
            with self.subTest(token=token):
                self.state["token"] = token
                with self.assertRaises(login.LoginError):
                    client.login("user@example.invalid", "test-password")


class TestLoginInputs(unittest.TestCase):
    def test_missing_or_invalid_config_is_redacted_and_does_not_request_network(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "bad.local.toml"
            invalid = [None, '[login]\npassword = "private-password" BROKEN',
                       '[login]\npassword = 123', '[login]\nopen_captcha = "yes"',
                       '[login]\nremember_days = true', '[login]\nremember_days = 7',
                       '[login]\ntimeout = nan', '[login]\ntoken_file = ""',
                       '[login]\npasswrod = "private-password"']
            for content in invalid:
                with self.subTest(content=content):
                    if content is not None:
                        config.write_text(content)
                    with mock.patch.object(login.LoginClient, "request") as request_mock, \
                            contextlib.redirect_stderr(io.StringIO()) as error:
                        self.assertEqual(login.main(["-c", str(config)]), 1)
                    self.assertNotIn("private-password", error.getvalue())
                    request_mock.assert_not_called()

    def test_token_file_cannot_overwrite_config(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "login.local.toml"
            write_config(config, portal="https://example.invalid", token_file=config.name)
            original = config.read_bytes()
            with contextlib.redirect_stderr(io.StringIO()) as error:
                self.assertEqual(login.main(["-c", str(config)]), 1)
            self.assertIn("不能指向登录配置", error.getvalue())
            self.assertEqual(config.read_bytes(), original)

    def test_default_config_is_based_on_project_not_working_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "login.local.toml"
            write_config(config, portal="https://example.invalid", token_file="private/token.txt")
            with mock.patch.object(login, "DEFAULT_CONFIG", config):
                settings, selected = login.load_login_config(None)
            self.assertEqual(selected, config)
            self.assertEqual(settings["output"], config.parent / "private/token.txt")

    def test_empty_environment_password_overrides_config_and_fails_before_network(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "login.local.toml"
            write_config(config, portal="https://example.invalid", email="user@example.invalid", password="test-password")
            with mock.patch.dict(os.environ, {"SUBLOADER_PASSWORD": ""}), \
                    mock.patch.object(login.LoginClient, "request") as request_mock, \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(login.main(["-c", str(config)]), 1)
            request_mock.assert_not_called()

    def test_malformed_page_is_data_not_executable_code(self):
        for html in ("<html>challenge</html>", "window.init_text = 'bad!data'",
                     "window.init_text = 'bad!" + "\u200c" * 8 + "'"):
            with self.subTest(html=html):
                with self.assertRaises(login.LoginError):
                    login.decode_init(html)

    def test_portal_validation(self):
        for portal in ("http://example.invalid", "https://user:secret@example.invalid",
                       "https://example.invalid/path", "https://example.invalid?token=secret",
                       "file:///tmp/page", "https://example.invalid:bad"):
            with self.subTest(portal=portal):
                with self.assertRaises(login.LoginError):
                    login.LoginClient(portal)
        for timeout in (0, -1, float("nan"), float("inf"), 121):
            with self.assertRaises(login.LoginError):
                login.LoginClient("https://example.invalid", timeout)

    def test_save_failure_keeps_previous_token_and_removes_tempfile(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "token.txt"
            output.write_text("previous-token\n")
            with mock.patch.object(login.os, "replace", side_effect=OSError("test failure")):
                with self.assertRaises(OSError):
                    login.save_token(output, "new-token")
            self.assertEqual(output.read_text(), "previous-token\n")
            self.assertEqual(list(Path(directory).iterdir()), [output])


if __name__ == "__main__":
    unittest.main()
