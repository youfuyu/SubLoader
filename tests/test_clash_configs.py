"""节点订阅与两份原生 YAML 扩展的组合、筛选和 Mihomo 兼容校验."""

import json
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.request

import yaml

from core import converter, runner
from core.config import PROJECT_ROOT
from core.validation import BUILTIN_POLICIES

MIHOMO = shutil.which('mihomo') or '/Applications/Clash Verge.app/Contents/MacOS/verge-mihomo'


def subscription(names):
    raw = [{'name': name, 'net_type': 'TROJAN', 'server': 'node.example.invalid',
            'server_port': 443, 'password': 'fixture-password'} for name in names]
    nodes, skipped = converter.normalize_nodes(raw)
    assert not skipped
    text = converter.to_clash_config(nodes, None, 'test')
    runner._validate_outputs(text, converter.to_qx_servers(nodes, None, 'test'), len(nodes))
    return yaml.safe_load(text)


def extension(name):
    return yaml.safe_load((PROJECT_ROOT / 'clash' / name).read_text())


def compose(names):
    return {**subscription(names), **extension('groups.yaml'), **extension('routing.yaml')}


def prepare_rule_cache(root, config):
    for provider in config['rule-providers'].values():
        path = root / provider['path']
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = ['192.0.2.0/24'] if provider['behavior'] == 'ipcidr' else ['+.example.invalid']
        path.write_text(yaml.safe_dump({'payload': payload}))
        provider['type'] = 'file'
        provider.pop('url')


class TestClashConfigs(unittest.TestCase):
    def test_each_file_owns_separate_fields(self):
        self.assertEqual(set(subscription(['日本JP'])), {'proxies'})
        self.assertEqual(set(extension('groups.yaml')), {'proxy-groups'})
        self.assertEqual(set(extension('routing.yaml')), {'rules', 'rule-providers'})

    def test_native_group_layout_and_latency_settings(self):
        groups = {group['name']: group for group in extension('groups.yaml')['proxy-groups']}
        self.assertEqual(list(groups), ['节点选择', '自动选择', '自动选择[HK]', '自动选择[JP]',
                                        '自动选择[TW]', '自动选择[US]', '手动选择'])
        self.assertEqual(groups['节点选择']['proxies'], ['自动选择', '手动选择'])
        self.assertEqual(groups['自动选择']['proxies'],
                         ['自动选择[HK]', '自动选择[JP]', '自动选择[TW]', '自动选择[US]'])
        for group in groups.values():
            if group['type'] == 'url-test':
                self.assertEqual((group['interval'], group['tolerance'], group['lazy']), (600, 100, True))
                self.assertTrue(group['include-all-proxies'])
                self.assertNotIn('use', group)
                self.assertEqual(group['empty-fallback'], 'REJECT')
                self.assertNotIn('proxies', group)
        self.assertTrue(groups['手动选择']['include-all-proxies'])
        self.assertNotIn('use', groups['手动选择'])
        self.assertEqual(groups['手动选择']['empty-fallback'], 'REJECT')

    def test_filters_follow_country_codes_and_ignore_transit_text(self):
        groups = {group['name']: group for group in extension('groups.yaml')['proxy-groups']}
        names = ['香港HK0', '日本JP · 台湾隧道2', '台湾TW2', '美国US1', '新加坡SG · 台湾隧道',
                 '日本jp2', 'RUSSIA', 'unknown', 'BUS1']
        expected = {'HK': ['香港HK0'], 'JP': ['日本JP · 台湾隧道2', '日本jp2'],
                    'TW': ['台湾TW2'], 'US': ['美国US1']}
        for code, matches in expected.items():
            pattern = groups['自动选择[%s]' % code]['filter']
            self.assertEqual([name for name in names if re.search(pattern, name)], matches)

    def test_default_group_names_do_not_collide_with_nodes(self):
        groups = {group['name'] for group in extension('groups.yaml')['proxy-groups']}
        data = subscription([*sorted(groups | BUILTIN_POLICIES), '节点选择 #2', 'PASS-RULE #2'])
        names = [proxy['name'] for proxy in data['proxies']]
        self.assertFalse(set(names) & (groups | BUILTIN_POLICIES))
        self.assertEqual(len(names), len(set(names)))
        self.assertIn('节点选择 #3', names)
        self.assertIn('PASS-RULE #3', names)

    def test_routing_references_declared_groups_and_providers(self):
        config = compose(['日本JP'])
        policies = {group['name'] for group in config['proxy-groups']} | BUILTIN_POLICIES
        self.assertEqual(config['rules'][:2], ['RULE-SET,private,DIRECT', 'RULE-SET,reject,REJECT'])
        self.assertEqual(config['rules'][-1], 'MATCH,节点选择')
        self.assertEqual(set(config['rule-providers']),
                         {'private', 'reject', 'direct', 'proxy', 'cncidr'})
        for rule in config['rules']:
            parts = rule.split(',')
            self.assertIn(parts[1 if parts[0] == 'MATCH' else 2], policies)
            if parts[0] == 'RULE-SET':
                self.assertIn(parts[1], config['rule-providers'])
        for provider in config['rule-providers'].values():
            self.assertEqual(provider['type'], 'http')
            self.assertEqual(provider['interval'], 86400)
            self.assertTrue(provider['url'].startswith('https://cdn.jsdelivr.net/'))

    @unittest.skipUnless(Path(MIHOMO).is_file(), 'optional Mihomo executable is not installed')
    def test_three_yaml_files_are_accepted_by_mihomo(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = compose(['香港HK', '日本JP', '台湾TW', '美国US', 'PASS-RULE', 'GLOBAL'])
            prepare_rule_cache(root, config)
            path = root / 'config.yaml'
            path.write_text(yaml.safe_dump(config, allow_unicode=True))
            result = subprocess.run([MIHOMO, '-t', '-d', tmp, '-f', str(path)],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(Path(MIHOMO).is_file(), 'optional Mihomo executable is not installed')
    def test_mihomo_filters_subscription_nodes_and_empty_regions(self):
        for names in (['日本JP A117 · 台湾隧道2', '香港HK10', '日本JP A83',
                       '台湾TW2', '香港HK2', '美国US1', 'unknown'], ['新加坡SG']):
            with self.subTest(names=names), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                config = compose(names)
                # 仅测试原生筛选,所有出站和健康检查限制在回环地址,不连接公网。
                config['proxies'] = [{'name': proxy['name'], 'type': 'direct'} for proxy in config['proxies']]
                expected = {proxy['name'] for proxy in config['proxies']}
                prepare_rule_cache(root, config)
                for group in config['proxy-groups']:
                    if group['type'] == 'url-test':
                        group.update(interval=0, url='http://127.0.0.1:9/unused')
                with socket.socket() as probe:
                    probe.bind(('127.0.0.1', 0))
                    port = probe.getsockname()[1]
                config.update({'external-controller': '127.0.0.1:%d' % port,
                               'mixed-port': 0, 'port': 0, 'socks-port': 0, 'tun': {'enable': False}})
                path = root / 'config.yaml'
                path.write_text(yaml.safe_dump(config, allow_unicode=True))
                process = subprocess.Popen([MIHOMO, '-d', tmp, '-f', str(path)],
                                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                try:
                    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                    deadline = time.monotonic() + 4
                    while True:
                        try:
                            with opener.open('http://127.0.0.1:%d/proxies' % port, timeout=.3) as response:
                                proxies = json.load(response)['proxies']
                            # 控制接口可能早于代理组初始化,需等待最终配置就绪.
                            if set(proxies.get('手动选择', {}).get('all', [])) != expected:
                                raise ValueError('proxy groups are still loading')
                            break
                        except (OSError, ValueError, urllib.error.URLError):
                            if process.poll() is not None or time.monotonic() > deadline:
                                self.fail('temporary Mihomo did not start')
                            time.sleep(.03)
                    self.assertCountEqual(proxies['手动选择']['all'], expected)
                    for code in ('HK', 'JP', 'TW', 'US'):
                        wanted = [name for name in expected if code in name]
                        group = proxies['自动选择[%s]' % code]
                        self.assertCountEqual(group['all'], wanted or ['REJECT'])
                finally:
                    process.terminate()
                    try:
                        process.communicate(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.communicate(timeout=3)
