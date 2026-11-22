"""安全边界回归测试:使用临时文件和回环 HTTP 服务,不访问外部网络."""

import copy
import json
import shutil
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

import yaml

from core import converter, fetcher, http_transport, runner, store
from core.config import Config, DEFAULTS, load_config
from core.paths import WRITE_LOCK_NAME
from core.validation import SS_METHODS


def raw_node(**overrides):
    return dict({'name': 'node', 'net_type': 'TROJAN', 'server': 'example.invalid',
                 'server_port': 443, 'password': 'test-secret'}, **overrides)


def isolated_config(root):
    data = copy.deepcopy(DEFAULTS)
    data['data'].update(raw_file=str(root / 'raw.json'), output_dir=str(root / 'out'))
    data['log']['file'] = str(root / 'app.log')
    return Config(data, root / 'config.toml')


class TestInputBoundaries(unittest.TestCase):
    def test_metadata_cannot_escape_comments(self):
        nodes, _ = converter.normalize_nodes([raw_node()])
        account = {'email': 'user\nexternal-controller: 0.0.0.0:9090\n#',
                   'vip_time_text': 'date\u2028mode: global', 'flow_cycle_left_text': 'a\x00b'}
        clash = converter.to_clash_config(nodes, account, 'date\nsecret: injected')
        qx = converter.to_qx_servers(nodes, account, 'date\n[server_remote]')
        parsed = yaml.safe_load(clash)
        self.assertNotIn('external-controller', parsed)
        self.assertNotIn('secret', parsed)
        self.assertEqual(set(parsed), {'proxies'})
        self.assertNotIn('\x00', qx)
        runner._validate_outputs(clash, qx, 1)

    def test_secrets_are_never_trimmed_or_coerced(self):
        for password in (' padded ', 'p\x00w', 'p\x85w', 'p\u2028w', {'key': 'value'}, ['pw'], 123):
            with self.subTest(password=repr(password)):
                nodes, skipped = converter.normalize_nodes([raw_node(password=password)])
                self.assertEqual(nodes, [])
                self.assertEqual(len(skipped), 1)
        nodes, _ = converter.normalize_nodes([raw_node(password='inside space')])
        self.assertEqual(nodes[0]['password'], 'inside space')

    def test_invalid_hosts_and_names_are_rejected(self):
        for override in ({'server': ['host']}, {'server': 'bad:port'}, {'name': 'node\x00'},
                         {'server': 'bad_host.invalid'}, {'name': {'text': 'node'}}):
            with self.subTest(override=override):
                self.assertEqual(converter.normalize_nodes([raw_node(**override)])[0], [])

    def test_bad_ss_method_is_rejected(self):
        self.assertEqual(converter.normalize_nodes([
            raw_node(net_type='SS', method='unknown-cipher')])[0], [])

    def test_self_check_rejects_corrupt_proxy_and_qx_fields(self):
        nodes, _ = converter.normalize_nodes([raw_node()])
        clash = converter.to_clash_config(nodes, None, 't')
        qx = converter.to_qx_servers(nodes, None, 't')
        parsed = yaml.safe_load(clash)
        parsed['proxies'].append('bad item')
        with self.assertRaises(ValueError):
            runner._validate_outputs(yaml.safe_dump(parsed), qx, 1)
        with self.assertRaises(ValueError):
            runner._validate_outputs(clash, qx.replace('password=test-secret', 'password=wrong'), 1)
        for corrupted in (qx + '\nunknown directive\n', qx.replace(':443,', ':+443,')):
            with self.subTest(corrupted=corrupted), self.assertRaises(ValueError):
                runner._validate_outputs(clash, corrupted, 1)
        parsed = yaml.safe_load(clash)
        parsed['rules'] = ['IP-CIDR,bad,PROXY']
        with self.assertRaises(ValueError):
            runner._validate_outputs(yaml.safe_dump(parsed), qx, 1)


class TestPathBoundaries(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cfg = isolated_config(self.root)

    def test_protected_path_matrix(self):
        cfg = self.cfg
        cases = [
            ('data', 'raw_file', str(cfg.path)),
            ('output', 'clash_file', 'app.log.1'),
            ('output', 'clash_file', WRITE_LOCK_NAME),
            ('data', 'raw_file', str(cfg.output_dir)),
        ]
        for section, key, value in cases:
            with self.subTest(section=section, key=key):
                other = Config(copy.deepcopy(cfg._data), cfg.path)
                other._data[section][key] = value
                if value == 'app.log.1':
                    other['log']['file'] = str(other.output_dir / 'app.log')
                self.assertTrue(other.validate())

    def test_case_aliases_are_rejected_before_writing(self):
        self.cfg['output'].update(clash_file='node.yaml', quantumultx_file='NODE.YAML')
        self.assertTrue(self.cfg.validate())
        with self.assertRaises(ValueError):
            store._write_many([(self.root / 'node', 'clash', False),
                               (self.root / 'NODE', 'qx', False)])
        with self.assertRaises(ValueError):
            store._write_many([(self.root / 'folder' / 'a', 'clash', False),
                               (self.root / 'FOLDER' / 'b', 'qx', False)])

    def test_direct_store_cannot_overwrite_loaded_config(self):
        self.cfg.path.write_text('[api]\ntoken="auto"\n')
        self.cfg['data']['raw_file'] = str(self.cfg.path)
        with self.assertRaises(ValueError):
            store.save_raw(self.cfg, {'code': 0}, None)
        self.assertTrue(self.cfg.path.read_text().startswith('[api]'))

    def test_retry_overflow_reports_config_error(self):
        self.cfg['schedule']['retry_interval_minutes'] = 1e308
        self.assertTrue(self.cfg.validate())

    def test_config_symlink_loop_is_a_clean_value_error(self):
        loop = self.root / 'config.toml'
        loop.symlink_to(loop.name)
        for path in (loop, None):
            with self.subTest(explicit=path is not None):
                with mock.patch('core.config.PROJECT_ROOT', self.root):
                    with self.assertRaisesRegex(ValueError, '符号链接循环'):
                        load_config(path)

    def test_different_configs_cannot_interleave_shared_outputs(self):
        first, second = isolated_config(self.root / 'a'), isolated_config(self.root / 'b')
        for cfg in (first, second):
            cfg['data']['output_dir'] = str(self.root / 'shared')
        entered, release = threading.Event(), threading.Event()
        failures = []
        original = store._write_many_locked
        def hold(files):
            entered.set()
            if not release.wait(3):
                raise RuntimeError('test timeout')
            return original(files)
        def write_first():
            try:
                store.save_bundle(first, {'generation': 'A'}, None, 'clash-A', 'qx-A')
            except Exception as exc:
                failures.append(exc)
        with mock.patch.object(store, '_write_many_locked', side_effect=hold):
            thread = threading.Thread(target=write_first)
            thread.start()
            try:
                self.assertTrue(entered.wait(3))
                with self.assertRaises(store.BusyError):
                    store.save_bundle(second, {'generation': 'B'}, None, 'clash-B', 'qx-B')
            finally:
                release.set()
                thread.join(3)
        self.assertFalse(failures)
        self.assertEqual(first.clash_path.read_text(), 'clash-A')
        self.assertEqual(first.quantumultx_path.read_text(), 'qx-A')
        self.assertFalse(second.raw_file.exists())

    def test_each_commit_or_fsync_failure_preserves_originals(self):
        for operation, count in [('replace', 6), ('fsync', 9)]:
            for failing_call in range(1, count + 1):
                with self.subTest(operation=operation, failing_call=failing_call), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    paths = [root / 'raw.json', root / 'clash.yaml', root / 'qx.txt']
                    for i, path in enumerate(paths):
                        path.write_text('old-%d' % i)
                    original = getattr(store.os, operation)
                    calls = 0
                    def fail_once(*args, **kwargs):
                        nonlocal calls
                        calls += 1
                        if calls == failing_call:
                            raise OSError('injected failure')
                        return original(*args, **kwargs)
                    with mock.patch.object(store.os, operation, side_effect=fail_once):
                        with self.assertRaises(OSError):
                            store._write_many([(p, 'new', True) for p in paths])
                    self.assertEqual([p.read_text() for p in paths], ['old-0', 'old-1', 'old-2'])
                    self.assertFalse(any(p.suffix in ('.tmp', '.backup', '.rollback') for p in root.iterdir()))


class FixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        try:
            if self.path.startswith('/redirect'):
                self.send_response(302)
                location = '/ok' if self.path in ('/redirect-same', '/redirect-body') else 'http://localhost:%d/ok' % self.server.server_port
                self.send_header('Location', location)
                if self.path == '/redirect-body':
                    self.send_header('Content-Length', '1000000')
                self.end_headers()
                return
            if self.path == '/slow-headers':
                self.wfile.write(b'HTTP/1.1 200 OK\r\nX-Drip: ')
                for _ in range(40):
                    self.wfile.write(b'x'); self.wfile.flush(); time.sleep(.03)
                self.wfile.write(b'\r\nContent-Length: 2\r\n\r\nok')
                return
            self.server.tokens.append(self.headers.get('X-Client-Token'))
            self.send_response(206 if self.path == '/partial' else 200)
            if self.path == '/chunked':
                self.send_header('Transfer-Encoding', 'chunked'); self.end_headers()
                self.wfile.write(b'2\r\nok\r\n0\r\n\r\n')
                return
            payload = b'{"code":0}'
            if self.path == '/utf8': payload = b'\xff'
            if self.path == '/large': payload = b'x' * 1024
            if self.path == '/stream-large': payload = b'x' * 1024
            if self.path == '/slow': payload = b'x' * 40
            if self.path != '/stream-large':
                self.send_header('Content-Length', str(len(payload) + (10 if self.path == '/truncated' else 0)))
            self.end_headers()
            if self.path == '/slow':
                for byte in payload:
                    self.wfile.write(bytes([byte])); self.wfile.flush(); time.sleep(.03)
            else:
                self.wfile.write(payload)
        except OSError:
            pass


class TestHTTPBoundaries(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), FixtureHandler)
        cls.server.tokens = []
        cls.thread = threading.Thread(target=cls.server.serve_forever, kwargs={'poll_interval': .02}, daemon=True)
        cls.thread.start()
        cls.base = 'http://127.0.0.1:%d' % cls.server.server_port

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join(3)

    def read(self, path, **kwargs):
        return fetcher._http_get_raw(fetcher._build_opener(True), self.base + path,
                                    kwargs.pop('timeout', 2), **kwargs)

    def test_same_origin_redirect_retains_authentication(self):
        self.assertEqual(json.loads(self.read('/redirect-same', headers={'X-Client-Token': 'dummy'})), {'code': 0})
        self.assertEqual(self.server.tokens[-1], 'dummy')

    def test_cross_origin_redirect_never_forwards_token(self):
        count = len(self.server.tokens)
        with self.assertRaises(urllib.error.URLError):
            self.read('/redirect-cross', headers={'X-Client-Token': 'dummy'})
        self.assertEqual(len(self.server.tokens), count)

    def test_anonymous_cross_origin_redirect_still_works(self):
        self.assertEqual(json.loads(self.read('/redirect-cross')), {'code': 0})

    def test_redirect_body_is_not_downloaded(self):
        self.assertEqual(json.loads(self.read('/redirect-body', max_bytes=128)), {'code': 0})

    def test_https_downgrade_is_rejected(self):
        request = urllib.request.Request('https://example.invalid/start')
        with self.assertRaises(urllib.error.URLError):
            http_transport.SafeRedirectHandler().redirect_request(
                request, None, 302, 'Found', {}, 'http://example.invalid/end')

    def test_slow_body_and_headers_obey_total_deadline(self):
        for path in ('/slow', '/slow-headers'):
            with self.subTest(path=path):
                start = time.monotonic()
                with self.assertRaises((TimeoutError, urllib.error.URLError)):
                    self.read(path, timeout=.2)
                self.assertLess(time.monotonic() - start, 1)

    def test_bounded_response_with_and_without_content_length(self):
        for path in ('/large', '/stream-large'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.read(path, max_bytes=128)

    def test_invalid_utf8_is_not_replaced(self):
        with self.assertRaises(UnicodeDecodeError):
            self.read('/utf8')

    def test_chunked_response_is_read_correctly(self):
        self.assertEqual(self.read('/chunked'), 'ok')

    def test_partial_or_truncated_response_is_rejected(self):
        for path in ('/partial', '/truncated'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.read(path)

MIHOMO = shutil.which('mihomo') or '/Applications/Clash Verge.app/Contents/MacOS/verge-mihomo'


@unittest.skipUnless(Path(MIHOMO).is_file(), 'optional Mihomo executable is not installed')
class TestClientCompatibility(unittest.TestCase):
    def test_supported_ss_methods_are_accepted_by_installed_core(self):
        raw = [raw_node(name=method, net_type='SS', method=method) for method in sorted(SS_METHODS)]
        nodes, skipped = converter.normalize_nodes(raw)
        self.assertFalse(skipped)
        clash = converter.to_clash_config(nodes, None, 'test')
        runner._validate_outputs(clash, converter.to_qx_servers(nodes, None, 'test'), len(nodes))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'config.yaml'
            path.write_text(clash)
            result = subprocess.run([MIHOMO, '-t', '-d', tmp, '-f', str(path)],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class TestHTTPSBoundaries(unittest.TestCase):
    @unittest.skipUnless(shutil.which('openssl'), 'openssl is needed to create a local TLS fixture')
    def test_tls_verification_and_https_transport(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cert, key = root / 'cert.pem', root / 'key.pem'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                            '-subj', '/CN=localhost', '-keyout', str(key), '-out', str(cert)],
                           check=True, capture_output=True, timeout=15)
            server = ThreadingHTTPServer(('127.0.0.1', 0), FixtureHandler)
            server.tokens = []
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .02}, daemon=True)
            thread.start()
            url = 'https://127.0.0.1:%d/ok' % server.server_port
            try:
                with self.assertRaises(urllib.error.URLError):
                    fetcher._http_get_raw(fetcher._build_opener(True), url, 2)
                self.assertEqual(json.loads(fetcher._http_get_raw(fetcher._build_opener(False), url, 2)), {'code': 0})
            finally:
                server.shutdown(); server.server_close(); thread.join(3)


if __name__ == '__main__':
    unittest.main()
