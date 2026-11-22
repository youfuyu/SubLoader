"""请求回退、完整执行流程和命令行的离线回归测试."""

import contextlib
import copy
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

from core import __main__ as cli
from core import converter, fetcher, runner, store
from core.config import Config, DEFAULTS, PROJECT_ROOT


def make_node(name="node"):
    return {"name": name, "server": "node.example.invalid", "server_port": 443,
            "net_type": "TROJAN", "password": "test-password",
            "quick_url": "trojan://pw@node.example.invalid:443?peer=sni.example.invalid&allowInsecure=1"}


def make_config(root=None):
    data = copy.deepcopy(DEFAULTS)
    data["api"].update(api_urls=["https://first.invalid", "https://second.invalid"], retry_per_url=0,
                       cloudapi_urls=["https://discovery.invalid/first", "https://discovery.invalid/second"])
    if root is not None:
        data["data"].update(raw_file=str(root / "raw.json"), output_dir=str(root / "out"))
        data["log"]["file"] = str(root / "app.log")
    return Config(data, None)


class TestFetcher(unittest.TestCase):
    def test_token_file_is_read_with_optional_line_ending(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "token.txt"
            cfg = make_config()
            cfg["api"]["token_file"] = str(path)
            for suffix in (b"", b"\n", b"\r\n"):
                path.write_bytes(b"file-token" + suffix)
                with mock.patch.object(fetcher, "read_token_from_wwss") as plist:
                    self.assertEqual(fetcher.resolve_token(cfg), "file-token")
                plist.assert_not_called()

    def test_explicit_token_takes_precedence_over_file_and_auto_still_reads_app(self):
        cfg = make_config()
        cfg["api"].update(token="inline-token", token_file="missing-token.txt")
        with mock.patch.object(fetcher, "read_token_from_file") as read_file:
            self.assertEqual(fetcher.resolve_token(cfg), "inline-token")
        read_file.assert_not_called()
        cfg["api"].update(token="auto", token_file="")
        with mock.patch.object(fetcher, "read_token_from_wwss", return_value="app-token"):
            self.assertEqual(fetcher.resolve_token(cfg), "app-token")

    def test_invalid_token_file_fails_without_fallback_or_secret_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private-token.txt"
            cfg = make_config()
            cfg["api"]["token_file"] = str(path)
            for raw in (None, b"", b" padded-secret ", b"secret\nextra", b"secret\r\nheader: bad",
                        b"\xff", b"a" * (fetcher.MAX_TOKEN_FILE_BYTES + 1)):
                with self.subTest(raw_type=type(raw).__name__):
                    if raw is not None:
                        path.write_bytes(raw)
                    with mock.patch.object(fetcher, "read_token_from_wwss") as plist:
                        with self.assertRaises(RuntimeError) as raised:
                            fetcher.resolve_token(cfg)
                    self.assertNotIn("padded-secret", str(raised.exception))
                    self.assertNotIn(str(path), str(raised.exception))
                    plist.assert_not_called()

    def test_invalid_responses_fall_back_to_next_domain(self):
        invalid = [None, [], {"code": 1, "message": "private-message"},
                   {"code": 0, "data": {}}, {"code": 0, "data": [{"name": "broken"}]}]
        valid = {"code": 0, "data": {"rows": [make_node()]}}
        for payload in invalid:
            with self.subTest(payload=payload):
                cfg = make_config()
                with mock.patch.object(fetcher, "_http_get", side_effect=[payload, valid]) as get:
                    base, result = fetcher._try_urls(cfg, object(), "/user/node/get-list", "token")
                self.assertEqual(base, "https://second.invalid")
                self.assertEqual(result, valid)
                self.assertEqual(get.call_count, 2)

    def test_all_domains_fail_without_exposing_error_credentials(self):
        with mock.patch.object(fetcher, "_http_get", side_effect=RuntimeError("secret-url-token")):
            with self.assertRaises(RuntimeError) as raised:
                fetcher._try_urls(make_config(), object(), "/test", "token")
        self.assertNotIn("secret-url-token", str(raised.exception))

    def test_discovery_filters_invalid_and_insecure_urls(self):
        cfg = make_config()
        payload = {"data": {"api_urls": [None, "", "file:///tmp/a", "http://unsafe.invalid",
                                        "https://ok.invalid/", "https://ok.invalid",
                                        "https://credential:secret@bad.invalid"]}}
        with mock.patch.object(fetcher, "_http_get", return_value=payload):
            self.assertEqual(fetcher.discover_api_urls(cfg, object()), ["https://ok.invalid"])

    def test_empty_discovery_result_tries_next_cloud(self):
        with mock.patch.object(fetcher, "_http_get", side_effect=[
                {"data": {"api_urls": [None]}},
                {"data": {"api_urls": ["https://ok.invalid"]}}]) as get:
            self.assertEqual(fetcher.discover_api_urls(make_config(), object()), ["https://ok.invalid"])
        self.assertEqual(get.call_count, 2)

    def test_account_failure_does_not_abort_node_fetch(self):
        cfg = make_config()
        valid = {"code": 0, "data": [make_node()]}
        with mock.patch.object(fetcher, "_build_opener"), \
                mock.patch.object(fetcher, "resolve_token", return_value="dummy"), \
                mock.patch.object(fetcher, "discover_api_urls", return_value=[]), \
                mock.patch.object(fetcher, "_try_urls", side_effect=[
                    ("https://first.invalid", valid), RuntimeError("account unavailable")]):
            result = fetcher.fetch(cfg)
        self.assertEqual(result["nodes_payload"], valid)
        self.assertIsNone(result["account"])


class TestRunner(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cfg = make_config(Path(self.tmp.name))
        self.result = {"nodes_payload": {"code": 0, "data": {"rows": [make_node()]}}, "account": None}
        self.paths = [self.cfg.raw_file, self.cfg.clash_path, self.cfg.quantumultx_path]
        for i, path in enumerate(self.paths):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("old-%d" % i)

    def assert_old_files(self):
        self.assertEqual([p.read_text() for p in self.paths], ["old-0", "old-1", "old-2"])

    def test_success_writes_matching_outputs_and_raw_with_backups(self):
        with mock.patch.object(fetcher, "fetch", return_value=self.result):
            self.assertTrue(runner.run_once(self.cfg))
        self.assertEqual(json.loads(self.cfg.raw_file.read_text())["response"], self.result["nodes_payload"])
        clash = yaml.safe_load(self.cfg.clash_path.read_text())
        self.assertEqual(len(clash["proxies"]), 1)
        self.assertIn("tag=node", self.cfg.quantumultx_path.read_text())
        for i, path in enumerate(self.paths):
            self.assertEqual(path.with_suffix(path.suffix + ".bak").read_text(), "old-%d" % i)

    def test_empty_nodes_preserve_all_files(self):
        self.result["nodes_payload"]["data"]["rows"] = []
        with mock.patch.object(fetcher, "fetch", return_value=self.result):
            self.assertFalse(runner.run_once(self.cfg))
        self.assert_old_files()

    def test_self_check_failure_preserves_raw_and_subscriptions(self):
        with mock.patch.object(fetcher, "fetch", return_value=self.result), \
                mock.patch.object(converter, "to_qx_servers", return_value="# no nodes"):
            self.assertFalse(runner.run_once(self.cfg))
        self.assert_old_files()

    def test_partial_commit_failure_rolls_back_all_three_files(self):
        replace = os.replace
        def fail_qx(src, dst):
            if Path(src).suffix == ".tmp" and Path(dst) == self.cfg.quantumultx_path:
                raise OSError("QX commit failed")
            return replace(src, dst)
        with mock.patch.object(fetcher, "fetch", return_value=self.result), \
                mock.patch.object(store.os, "replace", side_effect=fail_qx):
            with self.assertRaises(OSError):
                runner.run_once(self.cfg)
        self.assert_old_files()

    def test_node_update_does_not_fetch_or_embed_routing(self):
        with mock.patch.object(fetcher, "fetch", return_value=self.result):
            self.assertTrue(runner.run_once(self.cfg))
        self.assertEqual(set(yaml.safe_load(self.cfg.clash_path.read_text())), {"proxies"})

    def test_duplicate_names_are_rejected_by_self_check(self):
        nodes, _ = converter.normalize_nodes([make_node("A"), make_node("B")])
        nodes[1]["name"] = "A"
        with self.assertRaises(ValueError):
            runner._validate_outputs(converter.to_clash_config(nodes, None, "t"),
                                     converter.to_qx_servers(nodes, None, "t"), 2)

    def test_retry_waits_only_between_attempts_and_stops_on_success(self):
        self.cfg["schedule"]["retry_interval_minutes"] = 0.25
        with mock.patch.object(runner, "run_once", side_effect=[OSError("fail"), False, True]) as run, \
                mock.patch("time.sleep") as sleep:
            self.assertTrue(runner.run_with_retry(self.cfg))
        self.assertEqual(run.call_count, 3)
        self.assertEqual(sleep.call_args_list, [mock.call(15.0), mock.call(15.0)])

    def test_once_does_not_retry(self):
        with mock.patch.object(runner, "run_once", return_value=False) as run, \
                mock.patch("time.sleep") as sleep:
            self.assertFalse(runner.run_with_retry(self.cfg, attempts=1))
        self.assertEqual(run.call_count, 1)
        sleep.assert_not_called()


class TestCli(unittest.TestCase):
    def test_login_is_a_core_subcommand_with_config_on_either_side(self):
        from core import login
        for args in (["login"], ["-c", "custom.local.toml", "login"],
                     ["login", "-c", "custom.local.toml"]):
            with self.subTest(args=args), mock.patch.object(login, "run", return_value=0) as run, \
                    mock.patch.object(cli, "_load") as node_config:
                self.assertEqual(cli.main(args), 0)
                self.assertEqual(str(run.call_args.args[0].config),
                                 "None" if args == ["login"] else "custom.local.toml")
                node_config.assert_not_called()

    def test_options_work_before_and_after_subcommand(self):
        for args in (["--once", "run"], ["run", "--once"], ["--once"]):
            with self.subTest(args=args), mock.patch.object(cli, "cmd_run", return_value=0) as run:
                self.assertEqual(cli.main(args), 0)
                self.assertTrue(run.call_args.args[0].once)
        for args in (["-c", "custom.toml", "run"], ["run", "-c", "custom.toml"]):
            with self.subTest(args=args), mock.patch.object(cli, "cmd_run", return_value=0) as run:
                self.assertEqual(cli.main(args), 0)
                self.assertEqual(run.call_args.args[0].config, "custom.toml")

    def test_invalid_config_exits_before_logging_or_fetch(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.toml"
            path.write_text('[api]\nrequest_timeout = "bad"\n')
            with contextlib.redirect_stderr(io.StringIO()) as error, \
                    mock.patch.object(cli, "setup_logging") as logging_setup, \
                    self.assertRaises(SystemExit) as raised:
                cli.main(["-c", str(path)])
            self.assertEqual(raised.exception.code, 2)
            self.assertIn("request_timeout", error.getvalue())
            logging_setup.assert_not_called()

    def test_invalid_toml_does_not_echo_private_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.toml"
            path.write_text('[api]\ntoken = "private-secret" INVALID\n')
            with contextlib.redirect_stderr(io.StringIO()) as error, self.assertRaises(SystemExit) as raised:
                cli.main(["-c", str(path)])
            self.assertEqual(raised.exception.code, 2)
            self.assertNotIn("private-secret", error.getvalue())

    def test_launcher_works_from_other_directory_and_keeps_relative_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            uv = root / "uv"
            uv.write_text("#!/bin/sh\nexit 0\n")
            uv.chmod(0o755)
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ.get("PATH", ""))
            env.pop("PYTHONPATH", None)
            launcher = str(PROJECT_ROOT / "run.sh")
            help_result = subprocess.run([launcher, "--help"], cwd=root, env=env,
                                         capture_output=True, text=True, timeout=15)
            self.assertEqual(help_result.returncode, 0, help_result.stderr)
            (root / "custom.toml").write_text('[api]\nrequest_timeout = "bad"\n')
            result = subprocess.run([launcher, "run", "-c", "custom.toml"], cwd=root, env=env,
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 2)
            self.assertIn("request_timeout", result.stderr)


if __name__ == "__main__":
    unittest.main()
