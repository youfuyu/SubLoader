"""converter 单元测试:地区识别 / 节点归一化 / 名称排序 / 订阅格式."""

import unittest

from core import converter


def make_raw(name, ip="1.2.3.4", port=443, net="TROJAN", password="pw",
             quick="trojan://pw@1.2.3.4:443?peer=sni.example.com&allowInsecure=1#n"):
    return {
        "name": name, "server": "s.example.com", "server_ip": ip,
        "server_port": port, "net_type": net, "password": password,
        "method": "tls", "quick_url": quick,
    }


class TestRegion(unittest.TestCase):
    def test_basic_regions(self):
        cases = [
            ("IEPL · 深港专线 · HK0", "香港"),
            ("IEPL · 台湾专线B · TW2 · 深港IEPL", "台湾"),
            ("IEPL · 日本JP · A83 · Netflix日本 · ChatGPT解锁 · 台湾隧道2", "日本"),
            ("商务 · 南非ZA · 流媒体 · 台湾隧道2", "南非"),
            ("商务 · 新加坡SP · 43 · 禁视频 台湾隧道2", "新加坡"),
            ("商务 · 瑞典SW · 深港IEPL", "瑞典"),
            ("游戏 · 日本JP · 243 · 禁视频 深港IEPL", "日本"),
            ("实时负载: 电信- 移动- 联通23", "其他"),
        ]
        for name, want in cases:
            self.assertEqual(converter.detect_region(name), want, name)

    def test_nonstandard_codes(self):
        self.assertEqual(converter.detect_region("商务 · 波兰PO · 沪港IEPL"), "波兰")
        self.assertEqual(converter.detect_region("商务 · 韩国KR · 158"), "韩国")


class TestNormalize(unittest.TestCase):
    def test_invalid_nodes_skipped(self):
        raws = [
            make_raw("好节点"),
            make_raw("坏端口", port=0),
            make_raw("缺密码", password=""),
            make_raw("缺地址", ip=None),
        ]
        raws[3]["server"] = None
        valid, skipped = converter.normalize_nodes(raws)
        self.assertEqual(len(valid), 1)
        self.assertEqual(len(skipped), 3)

    def test_invalid_port_types_are_rejected(self):
        for port in (True, 443.5, float("inf"), float("nan")):
            with self.subTest(port=port):
                nodes, skipped = converter.normalize_nodes([make_raw("bad", port=port)])
                self.assertEqual(nodes, [])
                self.assertEqual(len(skipped), 1)

    def test_dedupe_names(self):
        raws = [make_raw("同名节点", ip="1.1.1.1"), make_raw("同名节点", ip="2.2.2.2")]
        valid, _ = converter.normalize_nodes(raws)
        names = [n["name"] for n in valid]
        self.assertEqual(names, ["同名节点", "同名节点 #2"])

    def test_generated_names_do_not_collide_with_original_names_or_groups(self):
        nodes, _ = converter.normalize_nodes([
            make_raw(name) for name in ("A", "A", "A #2", "PROXY", "AUTO", "DIRECT", "PASS-RULE", "GLOBAL")])
        names = [n["name"] for n in nodes]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(names[:3], ["A", "A #2", "A #3"])
        self.assertFalse(set(names) & {"PROXY", "AUTO", "DIRECT", "PASS-RULE", "GLOBAL"})

    def test_invalid_objects_and_qx_injection_are_skipped(self):
        nodes, skipped = converter.normalize_nodes([
            None, "bad", make_raw("tag, password=wrong"),
            make_raw("bad password", password="pw\ntag=other"), make_raw("ok")])
        self.assertEqual(len(nodes), 1)
        self.assertEqual(len(skipped), 4)

    def test_unknown_regions_are_last_and_each_region_uses_name_order(self):
        nodes, _ = converter.normalize_nodes([
            make_raw(name) for name in ("unknown Z", "南非 B", "unknown A", "南非 A")])
        self.assertEqual([n["name"] for n in nodes], ["南非 A", "南非 B", "unknown A", "unknown Z"])

    def test_tls_setting_is_used_by_both_formats(self):
        for verify in (True, False):
            with self.subTest(verify=verify):
                nodes, _ = converter.normalize_nodes([make_raw("node")], tls_verify=verify)
                proxy = converter.build_clash_proxies(nodes)[0]
                self.assertEqual(proxy["skip-cert-verify"], not verify)
                self.assertIn("tls-verification=%s" % str(verify).lower(),
                              converter.to_qx_servers(nodes, None, "t"))

    def test_quick_url_tls_setting_and_ipv6(self):
        nodes, _ = converter.normalize_nodes([
            make_raw("v6", ip="2001:db8::1", quick="trojan://pw@example:443?allowInsecure=0")])
        self.assertFalse(nodes[0]["skip_cert_verify"])
        self.assertIn("trojan=[2001:db8::1]:443", converter.to_qx_servers(nodes, None, "t"))

    def test_region_then_name_sort_preserves_parameters_and_both_output_orders(self):
        raws = [
            make_raw("IEPL · 日本JP · A117", ip="1.1.1.1"),
            make_raw("IEPL · 深港专线 · HK10", ip="2.2.2.2"),
            make_raw("IEPL · 深港专线 · HK2", ip="3.3.3.3"),
            make_raw("IEPL · 日本JP · A83", ip="4.4.4.4"),
        ]
        valid, _ = converter.normalize_nodes(raws)
        names = ["IEPL · 深港专线 · HK10", "IEPL · 深港专线 · HK2", "IEPL · 日本JP · A117", "IEPL · 日本JP · A83"]
        self.assertEqual([n["name"] for n in valid], names)
        self.assertEqual([n["host"] for n in valid], ["2.2.2.2", "3.3.3.3", "1.1.1.1", "4.4.4.4"])
        import yaml
        clash = yaml.safe_load(converter.to_clash_config(valid, None, "t"))
        self.assertEqual([proxy["name"] for proxy in clash["proxies"]], names)
        for group in (True, False):
            qx = converter.to_qx_servers(valid, None, "t", group=group)
            tags = [line.rsplit(", tag=", 1)[-1] for line in qx.splitlines()
                    if line.startswith(("trojan=", "shadowsocks="))]
            self.assertEqual(tags, names)

    def test_ss_node(self):
        raw = make_raw("ss 节点", net="SHADOWSOCKS", password="p", quick="")
        raw["method"] = "aes-256-gcm"
        valid, _ = converter.normalize_nodes([raw])
        self.assertEqual(valid[0]["type"], "ss")
        self.assertEqual(valid[0]["method"], "aes-256-gcm")


class TestClashOutput(unittest.TestCase):
    def test_subscription_contains_only_proxies(self):
        nodes, _ = converter.normalize_nodes([make_raw("IEPL · 深港专线 · HK0")])
        text = converter.to_clash_config(nodes, None, "t")
        import yaml
        cfg = yaml.safe_load(text)
        self.assertEqual(len(cfg["proxies"]), 1)
        self.assertEqual(cfg["proxies"][0]["type"], "trojan")
        self.assertEqual(cfg["proxies"][0]["sni"], "sni.example.com")
        self.assertEqual(set(cfg), {"proxies"})

    def test_legacy_routing_arguments_are_not_accepted(self):
        nodes, _ = converter.normalize_nodes([make_raw("IEPL · 深港专线 · HK0")])
        with self.assertRaises(TypeError):
            converter.to_clash_config(nodes, None, "t", rules=["MATCH,PROXY"])


class TestQxOutput(unittest.TestCase):
    def test_trojan_line_format(self):
        nodes, _ = converter.normalize_nodes([make_raw("IEPL · 深港专线 · HK0")])
        text = converter.to_qx_servers(nodes, None, "t")
        line = [ln for ln in text.splitlines() if ln.startswith("trojan=")][0]
        self.assertIn("trojan=1.2.3.4:443, password=pw, over-tls=true", line)
        self.assertIn("tls-host=sni.example.com", line)
        self.assertIn("tls-verification=false", line)
        self.assertTrue(line.endswith("tag=IEPL · 深港专线 · HK0"))

    def test_group_comments(self):
        raws = [make_raw("IEPL · 深港专线 · HK0"), make_raw("IEPL · 日本JP · V1")]
        nodes, _ = converter.normalize_nodes(raws)
        grouped = converter.to_qx_servers(nodes, None, "t", group=True)
        flat = converter.to_qx_servers(nodes, None, "t", group=False)
        self.assertIn("# ---- 香港 ----", grouped)
        self.assertNotIn("# ----", flat)


if __name__ == "__main__":
    unittest.main()
