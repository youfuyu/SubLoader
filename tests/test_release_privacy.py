"""公开源码范围、环境变量及账户隐私回归测试."""

import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from core import fetcher, runner
from core.config import Config, DEFAULTS, PROJECT_ROOT, load_config
from scripts.check_release import check_index, private_path, scan_text


class TestReleaseGuard(unittest.TestCase):
    def test_private_file_matrix(self):
        for path in ('config.toml', 'config.dev.toml', 'CONFIG.PROD.TOML', '.env', '.env.production',
                     '.workbuddy/memory/note.md', '.codex/session.json', 'data/raw.json',
                     'logs/run.log', 'one.yaml.backup', '.one.yaml.abcd.rollback',
                     'private.pem', 'out/subloader.lock', 'WestWorldVPN-clash.yaml', '.DS_Store'):
            with self.subTest(path=path):
                self.assertTrue(private_path(path))
        for path in ('config.example.toml', 'uv.lock', 'core/rules.py', 'tests/test_converter.py',
                     'README.md', '.githooks/pre-commit'):
            with self.subTest(path=path):
                self.assertFalse(private_path(path))

    def test_secret_report_never_contains_match_values(self):
        secret = 'gh' + 'p_' + 'a' * 36
        findings = scan_text('example.py', 'token = "%s"' % secret)
        self.assertTrue(findings)
        self.assertNotIn(secret, repr(findings))
        self.assertTrue(scan_text('example.py', 'value = "local-runtime-value"', ['local-runtime-value']))
        self.assertFalse(scan_text('example.py', 'email = "user@example.invalid"'))

    def test_credential_assignments_cover_environment_and_alias_keys(self):
        secret = 'fixture-' + 'a1b2c3d4' * 4
        for path, line in [
            ('.env.example', 'SUBLOADER_TOKEN=' + secret),
            ('settings.env', 'export TOKEN=' + secret),
            ('example.py', 'api_token = "' + secret + '"'),
            ('example.py', 'accessToken = "' + secret + '"'),
            ('example.json', '"node_password": "' + secret + '"'),
        ]:
            with self.subTest(path=path, line=line):
                findings = scan_text(path, line)
                self.assertTrue(findings)
                self.assertNotIn(secret, repr(findings))
        for path, line in [
            ('.env.example', 'SUBLOADER_TOKEN='),
            ('.env.example', 'SUBLOADER_TOKEN=${PROVIDED_AT_RUNTIME}'),
            ('example.py', 'api_token = runtime_credential_variable'),
            ('example.toml', 'subscription_url = "https://sub.example.invalid/private"'),
        ]:
            with self.subTest(path=path, line=line):
                self.assertEqual(scan_text(path, line), [])

    def test_clean_repository_guard_rejects_unquoted_environment_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(['git', 'init', '-b', 'main'], cwd=root, check=True, capture_output=True)
            secret = 'fixture-' + 'a1b2c3d4' * 4
            (root / '.env.example').write_text('SUBLOADER_TOKEN=' + secret + '\n')
            subprocess.run(['git', 'add', '.env.example'], cwd=root, check=True, capture_output=True)
            count, findings = check_index(root)
            self.assertEqual(count, 1)
            self.assertTrue(findings)
            self.assertNotIn(secret, repr(findings))

    def test_guard_reads_staged_version_instead_of_worktree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            def git(*args):
                subprocess.run(['git', '-C', tmp, *args], check=True, capture_output=True)
            git('init', '-b', 'main')
            path = root / 'sample.py'
            secret = 'github_' + 'pat_' + 'a' * 32
            path.write_text('value = "%s"' % secret)
            git('add', 'sample.py')
            path.write_text('value = "redacted"')
            count, findings = check_index(root)
            self.assertEqual(count, 1)
            self.assertTrue(findings)
            git('add', 'sample.py')
            self.assertEqual(check_index(root), (1, []))
            (root / 'config.toml').write_text('[api]\ntoken = "auto"\n')
            git('add', 'config.toml')
            self.assertTrue(check_index(root)[1])

    def test_gitignore_protects_real_runtime_artifacts(self):
        paths = ['config.toml', '.workbuddy/memory/note.md', 'data/raw.json', '.env.production',
                 '.config.yaml.random.rollback', '.output.random.backup', 'logs/run.log.1']
        result = subprocess.run(['git', '-C', str(PROJECT_ROOT), 'check-ignore', '--no-index', '--stdin'],
                                input='\n'.join(paths) + '\n', capture_output=True, text=True, check=True)
        self.assertEqual(set(result.stdout.splitlines()), set(paths))


class TestCredentialPrivacy(unittest.TestCase):
    def test_environment_overrides_are_in_memory_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'config.toml'
            original = '[api]\ntoken = "auto"\nsubscription_url = ""\n'
            path.write_text(original)
            with mock.patch.dict(os.environ, {'SUBLOADER_TOKEN': 'test-env-token',
                                             'SUBLOADER_SUBSCRIPTION_URL': 'https://sub.example.invalid/private'}):
                cfg = load_config(path)
                self.assertEqual(cfg.get('api', 'token'), 'test-env-token')
                self.assertEqual(cfg.get('api', 'subscription_url'), 'https://sub.example.invalid/private')
                self.assertEqual(cfg.validate(), [])
            self.assertEqual(path.read_text(), original)

    def test_empty_environment_secret_is_not_silently_replaced(self):
        with mock.patch.dict(os.environ, {'SUBLOADER_TOKEN': ''}):
            self.assertTrue(load_config().validate())

    def test_default_outputs_hide_account_but_raw_snapshot_keeps_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = copy.deepcopy(DEFAULTS)
            data['rules'].update(preset='builtin', output_dir=str(root / 'rules'))
            data['data'].update(raw_file=str(root / 'raw.json'), output_dir=str(root / 'out'))
            data['log']['file'] = str(root / 'app.log')
            cfg = Config(data, None)
            account = {'email': 'private-user@example.invalid', 'vip_time_text': 'private-expiry'}
            raw = {'code': 0, 'data': [{'name': 'node', 'net_type': 'TROJAN',
                                       'server': 'example.invalid', 'server_port': 443, 'password': 'dummy'}]}
            with mock.patch.object(fetcher, 'fetch', return_value={'nodes_payload': raw, 'account': account}):
                self.assertTrue(runner.run_once(cfg))
            for path in (cfg.clash_path, cfg.quantumultx_path):
                self.assertNotIn(account['email'], path.read_text())
                self.assertNotIn(account['vip_time_text'], path.read_text())
            self.assertEqual(json.loads(cfg.raw_file.read_text())['account'], account)

    def test_account_details_are_not_logged(self):
        cfg = Config(copy.deepcopy(DEFAULTS), None)
        account = {'email': 'private-user@example.invalid', 'flow_cycle_left_text': 'private-flow'}
        with mock.patch.object(fetcher, '_build_opener'), \
                mock.patch.object(fetcher, 'resolve_token', return_value='dummy'), \
                mock.patch.object(fetcher, 'discover_api_urls', return_value=[]), \
                mock.patch.object(fetcher, '_try_urls', side_effect=[
                    ('https://api.example.invalid', {'code': 0, 'data': []}),
                    ('https://api.example.invalid', {'code': 0, 'data': account})]), \
                self.assertLogs('core.fetch', level='INFO') as logs:
            fetcher.fetch(cfg)
        self.assertNotIn(account['email'], '\n'.join(logs.output))
        self.assertNotIn(account['flow_cycle_left_text'], '\n'.join(logs.output))


if __name__ == '__main__':
    unittest.main()
