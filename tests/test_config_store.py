"""config / store 单元测试(全部离线,不触网)."""

import os
import tempfile
import tomllib
import unittest
import copy
from pathlib import Path
from unittest import mock

from core import config as config_mod
from core import store


class TestConfig(unittest.TestCase):
    def setUp(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(mock.patch.object(config_mod, "PROJECT_ROOT", root))
        self.enterContext(mock.patch.dict(os.environ, {}, clear=True))

    def test_defaults_merge(self):
        cfg = config_mod.load_config()
        self.assertTrue(cfg.get("api", "api_urls"))
        self.assertEqual(cfg.get("api", "request_timeout"), 15)
        self.assertEqual(cfg.get("schedule", "max_attempts"), 3)

    def test_validate(self):
        cfg = config_mod.load_config()
        self.assertEqual(cfg.validate(), [])

    def test_resolve_path(self):
        p = config_mod.resolve_path("data/x.json")
        self.assertTrue(p.is_absolute())
        self.assertEqual(config_mod.resolve_path("/abs/x").as_posix(), "/abs/x")

    def test_token_file_path_and_write_conflicts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = copy.deepcopy(config_mod.DEFAULTS)
            cfg = config_mod.Config(data, root / "config.toml")
            self.assertIsNone(cfg.token_file)
            cfg["api"]["token_file"] = "private/token.txt"
            with mock.patch.object(config_mod, "PROJECT_ROOT", root):
                self.assertEqual(cfg.token_file, root / "private/token.txt")
                self.assertEqual(cfg.validate(), [])
                targets = [cfg.path, cfg.raw_file, cfg.clash_path, cfg.log_path,
                           cfg.raw_file.with_suffix(".json.bak"),
                           root / "login.local.toml"]
                for path in targets:
                    with self.subTest(path=path):
                        cfg["api"]["token_file"] = str(path)
                        self.assertTrue(cfg.validate())

    def test_explicit_missing_config_does_not_fall_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(FileNotFoundError):
                config_mod.load_config(Path(tmp) / "missing.toml")

    def test_missing_default_config_uses_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(config_mod, "PROJECT_ROOT", Path(tmp)):
                cfg = config_mod.load_config()
        self.assertIsNone(cfg.path)
        self.assertEqual(cfg._data, config_mod.DEFAULTS)

    def test_blank_file_options_use_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            text = "\n".join(
                "[%s]\n%s" % (section, "\n".join('%s = ""' % key for key in values))
                for section, values in config_mod.DEFAULTS.items())
            path.write_text(text)
            with mock.patch.dict(os.environ, {}, clear=True):
                cfg = config_mod.load_config(path)
            self.assertEqual(cfg._data, config_mod.DEFAULTS)
            self.assertEqual(path.read_text(), text)

    def test_explicit_false_zero_and_empty_lists_are_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            path.write_text('[api]\nfetch_account_info = false\nretry_per_url = 0\n'
                            'cloudapi_urls = []\napi_urls = []\n'
                            '[output]\nbackup_old = false\ninclude_quantumultx_group = false\n'
                            '[schedule]\nretry_interval_minutes = 0\n')
            with mock.patch.dict(os.environ, {}, clear=True):
                cfg = config_mod.load_config(path)
        for section, key in (("api", "fetch_account_info"), ("output", "backup_old"),
                             ("output", "include_quantumultx_group")):
            self.assertIs(cfg.get(section, key), False)
        for section, key in (("api", "retry_per_url"),
                             ("schedule", "retry_interval_minutes")):
            self.assertEqual(cfg.get(section, key), 0)
        self.assertEqual(cfg.get("api", "cloudapi_urls"), [])
        self.assertEqual(cfg.get("api", "api_urls"), [])
        errors = cfg.validate()
        self.assertEqual(len(errors), 1)
        self.assertIn("api_urls", errors[0])

    def test_example_lists_all_options_and_only_requires_api_address(self):
        path = Path(__file__).resolve().parent.parent / "config.example.toml"
        data = tomllib.loads(path.read_text())
        self.assertEqual(set(data), set(config_mod.DEFAULTS))
        for section, values in config_mod.DEFAULTS.items():
            with self.subTest(section=section):
                self.assertEqual(set(data[section]), set(values))
        with mock.patch.dict(os.environ, {}, clear=True):
            cfg = config_mod.load_config(path)
        self.assertEqual(len(cfg.validate()), 1)
        self.assertIn("api_urls", cfg.validate()[0])
        cfg["api"]["api_urls"] = ["https://api.example.invalid"]
        self.assertEqual(cfg.validate(), [])

    def test_defaults_are_independent(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "empty.toml"
            path.write_text("")
            cfg = config_mod.load_config(path)
            cfg["api"]["api_urls"].append("https://changed.invalid")
            self.assertNotIn("https://changed.invalid", config_mod.load_config(path)["api"]["api_urls"])
            self.assertNotIn("https://changed.invalid", config_mod.DEFAULTS["api"]["api_urls"])
            self.assertEqual(cfg.get("data", "output_dir"), "data/subscriptions")

    def test_invalid_configuration_returns_errors_instead_of_crashing(self):
        cases = [
            ("api", "request_timeout", "bad"), ("api", "request_timeout", float("nan")),
            ("api", "request_timeout", 10 ** 400),
            ("api", "retry_per_url", -1), ("schedule", "max_attempts", True),
            ("schedule", "retry_interval_minutes", float("inf")),
            ("api", "api_urls", "https://example.com"),
            ("api", "api_urls", ["file:///tmp/a"]),
            ("api", "api_urls", ["https://example.com?token=bad"]),
            ("api", "tls_verify", "false"),
            ("api", "token_file", 123), ("api", "token_file", " "),
            ("api", "token_file", "bad\x00path"),
            ("output", "clash_file", "../other.yaml"), ("data", "raw_file", None),
            ("output", "quantumultx_file", "WestWorldVPN-clash.yaml"),
        ]
        for section, key, value in cases:
            with self.subTest(section=section, key=key, value=value):
                data = copy.deepcopy(config_mod.DEFAULTS)
                data[section][key] = value
                self.assertTrue(config_mod.Config(data, None).validate())
        data = copy.deepcopy(config_mod.DEFAULTS)
        data["api"] = []
        self.assertTrue(config_mod.Config(data, None).validate())


class TestStore(unittest.TestCase):
    def test_atomic_write_and_backup(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "f.txt"
            store._atomic_write(target, "v1", backup=False)
            store._atomic_write(target, "v2", backup=True)
            self.assertEqual(target.read_text(), "v2")
            self.assertEqual((Path(tmp) / "f.txt.bak").read_text(), "v1")

    def test_run_lock_exclusive(self):
        with tempfile.TemporaryDirectory() as tmp:
            lock = Path(tmp) / "run.lock"
            with store.run_lock(lock):
                with self.assertRaises(store.BusyError):
                    with store.run_lock(lock):
                        pass
            # 释放后可再次获取
            with store.run_lock(lock):
                pass

    def test_failed_replace_preserves_old_target_and_cleans_temps(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "f.txt"
            target.write_text("old")
            replace = os.replace
            def fail_new(src, dst):
                if Path(src).suffix == ".tmp":
                    raise OSError("simulated commit failure")
                return replace(src, dst)
            with mock.patch.object(store.os, "replace", side_effect=fail_new):
                with self.assertRaises(OSError):
                    store._atomic_write(target, "new")
            self.assertEqual(target.read_text(), "old")
            self.assertEqual(target.with_suffix(".txt.bak").read_text(), "old")
            self.assertFalse(any(p.suffix in (".tmp", ".rollback", ".backup") for p in Path(tmp).iterdir()))

    def test_backup_failure_does_not_replace_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "f.txt"
            target.write_text("old")
            with mock.patch.object(store.os, "replace", side_effect=OSError("backup failed")):
                with self.assertRaises(OSError):
                    store._atomic_write(target, "new")
            self.assertEqual(target.read_text(), "old")

    def test_multi_file_failure_rolls_back_with_or_without_existing_files(self):
        for existing in (True, False):
            with self.subTest(existing=existing), tempfile.TemporaryDirectory() as tmp:
                first, second = Path(tmp) / "clash.yaml", Path(tmp) / "qx.txt"
                if existing:
                    first.write_text("old clash")
                    second.write_text("old qx")
                replace = os.replace
                def fail_second(src, dst):
                    if Path(dst) == second and Path(src).suffix == ".tmp":
                        raise OSError("second commit failed")
                    return replace(src, dst)
                with mock.patch.object(store.os, "replace", side_effect=fail_second):
                    with self.assertRaises(OSError):
                        store._write_many([(first, "new clash", False), (second, "new qx", False)])
                if existing:
                    self.assertEqual(first.read_text(), "old clash")
                    self.assertEqual(second.read_text(), "old qx")
                else:
                    self.assertFalse(first.exists())
                    self.assertFalse(second.exists())

    def test_lock_contender_does_not_truncate_owner_pid(self):
        with tempfile.TemporaryDirectory() as tmp:
            lock = Path(tmp) / "run.lock"
            with store.run_lock(lock):
                owner = lock.read_text()
                with self.assertRaises(store.BusyError):
                    with store.run_lock(lock):
                        pass
                self.assertEqual(lock.read_text(), owner)

    def test_failed_rollback_keeps_recovery_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            first, second = Path(tmp) / "one.txt", Path(tmp) / "two.txt"
            first.write_text("recover me")
            second.write_text("old second")
            replace = os.replace
            def fail_commit_and_rollback(src, dst):
                if ((Path(dst) == second and Path(src).suffix == ".tmp")
                        or Path(src).suffix == ".rollback"):
                    raise OSError("filesystem unavailable")
                return replace(src, dst)
            with mock.patch.object(store.os, "replace", side_effect=fail_commit_and_rollback), \
                    self.assertLogs("core.store", level="ERROR"), self.assertRaises(OSError):
                store._write_many([(first, "new first", False), (second, "new second", False)])
            recovery = list(Path(tmp).glob(".*.rollback"))
            self.assertEqual(len(recovery), 1)
            self.assertEqual(recovery[0].read_text(), "recover me")

    def test_backup_path_collision_is_rejected_before_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp) / "f.txt"
            first.write_text("old")
            with self.assertRaises(ValueError):
                store._write_many([(first, "new", True), (Path(tmp) / "f.txt.bak", "bad", False)])
            self.assertEqual(first.read_text(), "old")


if __name__ == "__main__":
    unittest.main()
