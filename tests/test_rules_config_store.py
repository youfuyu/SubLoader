"""rules / config / store 单元测试(全部离线,不触网)."""

import os
import tempfile
import time
import unittest
import copy
from pathlib import Path
from unittest import mock

from core import config as config_mod
from core import rules as rules_mod
from core import store


class TestConfig(unittest.TestCase):
    def test_defaults_merge(self):
        cfg = config_mod.load_config()  # 无 config.toml 的场景由 DEFAULTS 兜底
        self.assertTrue(cfg.get("api", "api_urls"))
        self.assertEqual(cfg.get("rules", "preset"), "github")
        self.assertEqual(cfg.get("schedule", "max_attempts"), 3)

    def test_validate(self):
        cfg = config_mod.load_config()
        self.assertEqual(cfg.validate(), [])

    def test_resolve_path(self):
        p = config_mod.resolve_path("data/x.json")
        self.assertTrue(p.is_absolute())
        self.assertEqual(config_mod.resolve_path("/abs/x").as_posix(), "/abs/x")

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

    def test_defaults_are_independent(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "empty.toml"
            path.write_text("")
            cfg = config_mod.load_config(path)
            cfg["api"]["api_urls"].append("https://changed.invalid")
            self.assertNotIn("https://changed.invalid", config_mod.load_config(path)["api"]["api_urls"])
            self.assertNotIn("https://changed.invalid", config_mod.DEFAULTS["api"]["api_urls"])
            self.assertEqual(cfg.get("api", "subscription_url"), "")
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
            ("api", "tls_verify", "false"), ("rules", "preset", "typo"),
            ("rules", "mirror_urls", ["https://example.com/{missing}"]),
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


class TestRulesFiles(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.cfg = mock.MagicMock()
        self.cfg.get.side_effect = self._cfg_get
        self._opts = {
            ("rules", "output_dir", "data/rules"): str(self.dir),
            ("rules", "refresh_days", 7): 7,
        }

    def _cfg_get(self, section, key, default=None):
        return self._opts.get((section, key, default), default)

    def _write_rule(self, name, lines=200):
        values = ["10.%d.0.0/16" % i if name == "cncidr" else "+.x%d.com" % i
                  for i in range(lines)]
        payload = "payload:\n" + "\n".join("  - '%s'" % item for item in values)
        (self.dir / ("%s.yaml" % name)).write_text(payload)

    def test_all_files_exist(self):
        for name in rules_mod.RULE_FILES:
            self._write_rule(name)
        self.assertTrue(rules_mod.all_files_exist(self.cfg))

    def test_missing_file_detected(self):
        self._write_rule("reject")
        self.assertFalse(rules_mod.all_files_exist(self.cfg))

    def test_is_fresh(self):
        for name in rules_mod.RULE_FILES:
            self._write_rule(name)
        self.assertTrue(rules_mod.is_fresh(self.cfg))
        # 改 mtime 到 8 天前 -> 过期
        old = time.time() - 8 * 86400
        for name in rules_mod.RULE_FILES:
            os.utime(self.dir / ("%s.yaml" % name), (old, old))
        self.assertFalse(rules_mod.is_fresh(self.cfg))

    def test_download_validation_rejects_bad_payload(self):
        bad = "not: yaml payload"
        with mock.patch.object(rules_mod, "_http_get_raw", return_value=bad):
            self.assertFalse(rules_mod._download_one(self.cfg, "reject"))

    def test_download_ok_writes_file(self):
        payload = "payload:\n" + "\n".join("  - '+.x%d.com'" % i for i in range(150))
        with mock.patch.object(rules_mod, "_http_get_raw", return_value=payload):
            self.assertTrue(rules_mod._download_one(self.cfg, "reject"))
        self.assertTrue((self.dir / "reject.yaml").exists())

    def test_corrupt_fresh_cache_is_not_reused(self):
        for name in rules_mod.RULE_FILES:
            self._write_rule(name)
        (self.dir / "direct.yaml").write_text("payload: []")
        with mock.patch.object(rules_mod, "download_all", return_value=False):
            self.assertFalse(rules_mod.ensure_rules(self.cfg))

    def test_valid_stale_cache_survives_download_failure(self):
        for name in rules_mod.RULE_FILES:
            self._write_rule(name)
            os.utime(self.dir / (name + ".yaml"), (0, 0))
        with mock.patch.object(rules_mod, "download_all", return_value=False):
            self.assertTrue(rules_mod.ensure_rules(self.cfg))

    def test_invalid_entries_are_rejected(self):
        for name, text in (("reject", "payload:\n" + "  - 42\n" * 100),
                           ("cncidr", "payload:\n" + "  - 'not-a-network'\n" * 100)):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    rules_mod._validate_rule_text(text, name)

    def test_rule_update_uses_directory_lock(self):
        with store.run_lock(self.dir / ".subloader.lock"):
            with self.assertRaises(store.BusyError), \
                    mock.patch.object(rules_mod, "_download_one") as download:
                rules_mod.download_all(self.cfg)
            download.assert_not_called()

    def test_unwritable_rule_directory_triggers_fallback(self):
        with mock.patch.object(rules_mod, "download_all", side_effect=PermissionError("locked")):
            self.assertFalse(rules_mod.ensure_rules(self.cfg))


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
