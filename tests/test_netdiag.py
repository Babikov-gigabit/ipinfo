# -*- coding: utf-8 -*-
"""Тесты разбора и логики диагностики. Запуск: python -m unittest discover tests"""

import ctypes
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netdiag import adapters as ad, config, diagnose, probes, report, winsys  # noqa: E402


def adapter(name, ipv4=(), up=True, iftype=6, gateway=(), dns=(), index=1, desc=""):
    return {"index": index, "iftype": iftype, "name": name, "description": desc,
            "type": {6: "Ethernet", 71: "Wi-Fi", 53: "Виртуальный"}.get(iftype, "?"),
            "status": "Up" if up else "Down", "up": up, "ipv4": list(ipv4), "ipv6": [],
            "gateway": list(gateway), "dns": list(dns), "mac": "-", "mtu": 1500,
            "speed": "-", "loopback": False}


PING_OK = {"sent": 4, "received": 4, "loss_pct": 0, "errors": {},
           "min_ms": 10, "avg_ms": 12, "max_ms": 15}
PING_FAIL = {"sent": 4, "received": 0, "loss_pct": 100,
             "errors": {"превышено время ожидания": 4}}


class StructTest(unittest.TestCase):
    def test_mib_if_row2_size_matches_windows_x64(self):
        self.assertEqual(ctypes.sizeof(ad.MIB_IF_ROW2), 1352)
        self.assertEqual(ad.MIB_IF_ROW2.InOctets.offset, 1208)

    def test_icmp_echo_reply_size_x64(self):
        if ctypes.sizeof(ctypes.c_void_p) == 8:
            self.assertEqual(ctypes.sizeof(probes._ICMP_ECHO_REPLY), 40)


class ConfigTest(unittest.TestCase):
    def test_parse_endpoint(self):
        self.assertEqual(config.parse_endpoint("vpn.example.ru:4433/UDP"),
                         ("vpn.example.ru", 4433, "udp"))
        self.assertEqual(config.parse_endpoint("10.1.1.1"), ("10.1.1.1", 443, "tcp"))

    def test_load_user_file(self):
        text = ("[vpn]\nmain = vpn1.example.ru:443/tcp\nres = 1.2.3.4:443\n"
                "[internal]\ndc = 10.0.0.1 ; контроллер\n"
                "[logs]\ncont = %ProgramData%\\Continent\\*.log\n")
        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False,
                                         encoding="utf-8-sig") as f:
            f.write(text)
        try:
            cfg = config.load(f.name)
        finally:
            os.unlink(f.name)
        self.assertEqual([s["name"] for s in cfg["vpn"]], ["main", "res"])
        self.assertEqual(cfg["internal"], [{"name": "dc", "host": "10.0.0.1"}])
        self.assertEqual(cfg["internet"], ["1.1.1.1", "8.8.8.8", "ya.ru"])
        self.assertIn("cont", cfg["logs"])

    def test_sample_has_no_servers(self):
        cfg = config.load(os.devnull + "-missing")
        self.assertEqual(cfg["vpn"], [])
        self.assertTrue(cfg["rdp"])


class ParseTest(unittest.TestCase):
    WLAN_RU = """
    Имя                    : Беспроводная сеть
    Состояние              : подключено
    SSID                   : HomeNet
    BSSID                  : aa:bb:cc:dd:ee:ff
    Тип радио              : 802.11ax
    Канал                  : 36
    Скорость приема (Мбит/с)  : 573.5
    Сигнал                 : 71%
"""
    WLAN_EN = """
    Name                   : Wi-Fi
    State                  : connected
    SSID                   : Office
    AP BSSID               : 11:22:33:44:55:66
    Band                   : 5 GHz
    Channel                : 44
    Radio type             : 802.11ac
    Signal                 : 38%
"""

    def test_wlan_ru(self):
        w = winsys.parse_wlan(self.WLAN_RU)
        self.assertEqual(w["ssid"], "HomeNet")
        self.assertEqual(w["bssid"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(w["signal_pct"], 71)
        self.assertEqual(w["channel"], 36)
        self.assertEqual(w["radio"], "802.11ax")

    def test_wlan_en(self):
        w = winsys.parse_wlan(self.WLAN_EN)
        self.assertEqual(w["ssid"], "Office")
        self.assertEqual(w["bssid"], "11:22:33:44:55:66")
        self.assertEqual(w["signal_pct"], 38)
        self.assertEqual(w["band"], "5 GHz")

    def test_listeners_ru(self):
        out = """
Активные подключения

  Имя    Локальный адрес        Внешний адрес          Состояние       PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1000
  TCP    0.0.0.0:3389           0.0.0.0:0              ПРОСЛУШИВАНИЕ   1200
  TCP    10.5.5.5:50000         10.0.0.1:3389          ESTABLISHED     4
  TCP    [::]:3389              [::]:0                 ПРОСЛУШИВАНИЕ   1200
"""
        self.assertEqual(winsys.parse_listeners(out, 3389), ["0.0.0.0", "[::]"])
        self.assertEqual(winsys.parse_listeners(out, 3390), [])

    def test_rdp_firewall_profile(self):
        fw = {"rdp_rules": [{"enabled": "True", "direction": "Inbound", "action": "Allow",
                             "profile": 1 | 2}],
              "firewall": [{"name": "Public", "enabled": "True"}]}
        self.assertTrue(winsys.rdp_allowed_for("Частная", fw))
        self.assertFalse(winsys.rdp_allowed_for("Общедоступная", fw))
        self.assertTrue(winsys.firewall_enabled_for("Общедоступная", fw))


class DiagnoseTest(unittest.TestCase):
    """Сценарии с подменёнными сетевыми вызовами."""

    def setUp(self):
        self.cfg = config.load(os.devnull + "-missing")
        self.cfg["internet"] = ["1.1.1.1"]
        self.cfg["vpn"] = [{"name": "main", "host": "5.5.5.5", "port": 443, "proto": "tcp"}]
        self.cfg["internal"] = [{"name": "dc", "host": "10.0.0.1"}]
        self.cfg["rdp"] = False
        self.lan = adapter("Ethernet", ["192.168.1.10/24"], gateway=["192.168.1.1"],
                           dns=["192.168.1.1"], index=5)
        self.vpn = adapter("Continent 4", ["10.20.30.40/32"], iftype=53, index=9,
                           desc="Continent TLS Adapter")

    def run_diag(self, adapters, ping=None, best=None, stats=None, tcp=(True, 20),
                 ext=("8.8.4.4", None), devices=None):
        ping = ping or {}
        stats = stats or {}
        with mock.patch.object(ad, "get_adapters", return_value=adapters), \
                mock.patch.object(probes, "ping", side_effect=lambda ip, *a, **k:
                                  ping.get(ip, PING_OK)), \
                mock.patch.object(probes, "resolve4", side_effect=lambda h, *a, **k: (h, 0.0)), \
                mock.patch.object(probes, "find_mtu", return_value=1400), \
                mock.patch.object(probes, "tcp_connect", return_value=tcp), \
                mock.patch.object(probes, "external_ip", return_value=ext), \
                mock.patch.object(ad, "best_interface", side_effect=lambda ip:
                                  (best or {}).get(ip, 9)), \
                mock.patch.object(ad, "if_stats", side_effect=lambda idx:
                                  stats.pop(0) if isinstance(stats, list) and stats else None), \
                mock.patch.object(winsys, "net_devices", return_value=devices), \
                mock.patch.object(winsys, "wifi_info", return_value=None):
            return diagnose.run(self.cfg)

    def test_all_good(self):
        d = self.run_diag([self.lan, self.vpn])
        self.assertEqual(d["tunnels"], ["Continent 4"])
        self.assertIn("работает", " ".join(d["verdict"]))

    def test_no_tunnel(self):
        d = self.run_diag([self.lan])
        self.assertIn("Туннель VPN не поднят.", d["verdict"])

    def test_tunnel_up_but_no_return_traffic(self):
        base = {"rx_bytes": 1000, "tx_bytes": 1000, "rx_packets": 1, "tx_packets": 1,
                "rx_errors": 0, "tx_errors": 0, "rx_discards": 0, "tx_discards": 0}
        after = dict(base, tx_bytes=5000)
        d = self.run_diag([self.lan, self.vpn], ping={"10.0.0.1": PING_FAIL},
                          stats=[base, after])
        v = " ".join(d["verdict"])
        self.assertIn("сервер не возвращает трафик", v)

    def test_route_conflict_with_home_lan(self):
        home = adapter("Wi-Fi", ["10.0.0.50/24"], iftype=71, gateway=["10.0.0.1"], index=7)
        d = self.run_diag([home, self.vpn], best={"10.0.0.1": 7})
        v = " ".join(d["verdict"])
        self.assertIn("конфликт адресов", v)
        self.assertTrue(any(c["name"] == "Конфликт адресов" for c in d["checks"]))

    def test_vpn_server_port_blocked(self):
        d = self.run_diag([self.lan], tcp=(False, "нет ответа"))
        self.assertIn("ни один VPN-сервер не доступен", " ".join(d["verdict"]))

    def test_internet_down_router_up(self):
        d = self.run_diag([self.lan], ping={"1.1.1.1": PING_FAIL, "5.5.5.5": PING_FAIL},
                          tcp=(False, "нет ответа"), ext=(None, "timeout"))
        self.assertIn("Роутер отвечает, но интернета нет: проблема у провайдера.", d["verdict"])
        self.assertTrue(any(c["name"] == "Роутер 192.168.1.1" and c["status"] == "ok"
                            for c in d["checks"]))

    def test_apipa(self):
        bad = adapter("Ethernet", ["169.254.10.2/16"], index=5)
        d = self.run_diag([bad])
        self.assertIn("DHCP", " ".join(d["verdict"]))

    def test_rdp_blocked_by_firewall_on_public_profile(self):
        self.cfg["rdp"] = True
        rdp = {"edition": "Professional", "home_edition": False, "enabled": True, "port": 3389,
               "nla": True, "service_state": 4, "service_text": "работает",
               "listening_on": ["0.0.0.0"]}
        fw = {"profiles": [{"index": 9, "alias": "Continent 4", "category": 0,
                            "category_text": "Общедоступная"}],
              "firewall": [{"name": "Public", "enabled": "True"}],
              "rdp_rules": [{"enabled": "True", "direction": "Inbound", "action": "Allow",
                             "profile": 1 | 2}]}
        with mock.patch.object(winsys, "rdp_info", return_value=rdp), \
                mock.patch.object(winsys, "firewall_info", return_value=fw):
            d = self.run_diag([self.lan, self.vpn])
        v = " ".join(d["verdict"])
        self.assertIn("RDP к этому ПК не заработает", v)
        self.assertIn("Общедоступная", v)

    def test_continent_adapter_missing(self):
        devs = [{"name": "Intel Ethernet", "status": "OK", "problem": 0, "present": True,
                 "problem_text": ""}]
        d = self.run_diag([self.lan], devices=devs)
        v = " ".join(d["verdict"])
        self.assertIn("Виртуальный адаптер Континент не найден", v)
        self.assertNotIn("OpenConnect", v)

    def test_continent_adapter_disabled(self):
        devs = [{"name": "Континент 4 Virtual Adapter", "status": "Error", "problem": 22,
                 "present": True, "problem_text": winsys.PNP_PROBLEM[22]}]
        d = self.run_diag([self.lan], devices=devs)
        self.assertIn("адаптер отключён", " ".join(d["verdict"]))

    def test_devices_not_checked_when_tunnel_up(self):
        d = self.run_diag([self.lan, self.vpn], devices=[])
        self.assertFalse(any(c["name"].startswith("Адаптер") for c in d["checks"]))

    def test_report_text_and_zip(self):
        d = self.run_diag([self.lan, self.vpn])
        text = report.format_text(d)
        self.assertIn("ИТОГ", text)
        with tempfile.TemporaryDirectory() as tmp:
            logdir = os.path.join(tmp, "vpnlogs")
            os.makedirs(logdir)
            with open(os.path.join(logdir, "a.log"), "w") as f:
                f.write("tunnel up\n")
            cfg = dict(self.cfg, logs={"continent": os.path.join(logdir, "*.log")})
            with mock.patch.object(winsys, "system_dumps", return_value={"x.txt": "y"}), \
                    mock.patch("netdiag.report.data_dir", return_value=tmp):
                path = report.build_zip(d, cfg, os.path.join(tmp, "r.zip"))
            import zipfile
            names = zipfile.ZipFile(path).namelist()
        self.assertIn("report.txt", names)
        self.assertIn("report.json", names)
        self.assertIn("vpn_logs/continent/a.log", names)
        self.assertIn("system/x.txt", names)


if __name__ == "__main__":
    unittest.main()
