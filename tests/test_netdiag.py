# -*- coding: utf-8 -*-
"""Тесты разбора и логики диагностики. Запуск: python -m unittest discover tests"""

import ctypes
import datetime
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netdiag import sysutil, live, session, continent, adapters as ad, config, diagnose, monitor, probes, report, winsys  # noqa: E402


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
        self.assertFalse(cfg["rdp"])  # входящий RDP по умолчанию не проверяется
        self.assertEqual(cfg["rdp_targets"], [])

    def test_rdp_targets(self):
        self.assertEqual(config._rdp_target("10.1.1.5"), {"host": "10.1.1.5", "port": 3389})
        self.assertEqual(config._rdp_target("ts.corp:3390"), {"host": "ts.corp", "port": 3390})


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
                 ext=("8.8.4.4", None), devices=None, cont=None, tls=None):
        ping = ping or {}
        cont = cont or {"install": None, "servers": [], "config_error": None, "log_dirs": [],
                        "collector": None}
        stats = stats or {}
        with mock.patch.object(ad, "get_adapters", return_value=adapters), \
                mock.patch.object(probes, "ping", side_effect=lambda ip, *a, **k:
                                  ping.get(ip, PING_OK)), \
                mock.patch.object(probes, "resolve4", side_effect=lambda h, *a, **k: (h, 0.0)), \
                mock.patch.object(probes, "find_mtu", return_value=1400), \
                mock.patch.object(probes, "tcp_connect", **(
                    {"side_effect": tcp} if callable(tcp) else {"return_value": tcp})), \
                mock.patch.object(probes, "external_ip", return_value=ext), \
                mock.patch.object(ad, "best_interface", side_effect=lambda ip:
                                  (best or {}).get(ip, 9)), \
                mock.patch.object(ad, "if_stats", side_effect=lambda idx:
                                  stats.pop(0) if isinstance(stats, list) and stats else None), \
                mock.patch.object(winsys, "net_devices", return_value=devices), \
                mock.patch.object(winsys, "wifi_info", return_value=None), \
                mock.patch.object(continent, "info", return_value=cont), \
                mock.patch.object(probes, "tls_probe", side_effect=lambda ip, *a, **k: (
                    tls or {}).get(ip, {"ok": False, "error": "handshake failure"})):
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

    def test_other_vpn_is_not_an_error_when_all_works(self):
        happ = adapter("happ-tun", ["172.19.0.1/30"], iftype=53, index=12,
                       desc="sing-tun Tunnel")
        d = self.run_diag([self.lan, happ, self.vpn])
        self.assertEqual(d["other_vpn"], ["happ-tun"])
        self.assertEqual(d["tunnels"], ["Continent 4"])
        self.assertNotIn("другой VPN", " ".join(d["verdict"]))
        self.assertTrue(any(c["name"] == "Другой VPN" and c["status"] == "info"
                            for c in d["checks"]))

    def test_vpn_server_routed_through_other_vpn(self):
        happ = adapter("happ-tun", ["172.19.0.1/30"], iftype=53, index=12,
                       desc="sing-tun Tunnel")
        d = self.run_diag([self.lan, happ, self.vpn], best={"5.5.5.5": 12, "1.1.1.1": 12})
        v = " ".join(d["verdict"])
        self.assertIn("идёт через другой VPN (main через «happ-tun»)", v)
        inet = next(c for c in d["checks"] if c["name"] == "1.1.1.1")
        self.assertIn("через «happ-tun»", inet["summary"])

    def test_virtual_adapter_without_gateway_is_info(self):
        vbox = adapter("Ethernet 3", ["192.168.56.1/24"], index=4,
                       desc="VirtualBox Host-Only Ethernet Adapter")
        d = self.run_diag([self.lan, vbox, self.vpn])
        c = next(c for c in d["checks"] if c["name"].startswith("Ethernet 3"))
        self.assertEqual(c["status"], "info")

    def test_internal_defaults_to_tunnel_dns(self):
        self.cfg["internal"] = []
        vpn = dict(self.vpn, dns=["10.61.30.91", "78.88.8.8"])
        d = self.run_diag([self.lan, vpn])
        names = [c["name"] for c in d["checks"] if c["group"] == "Туннель"]
        self.assertIn("DNS туннеля (10.61.30.91)", names)
        self.assertNotIn("DNS туннеля (78.88.8.8)", names)

    def test_rdp_outbound_targets(self):
        self.cfg["rdp_targets"] = [{"host": "10.0.0.5", "port": 3389},
                                   {"host": "10.0.0.6", "port": 3389}]
        with mock.patch.object(diagnose, "_probe_rdp", side_effect=lambda h, p: {
                "host": h, "ip": h, "port": p, "tcp_ok": h == "10.0.0.5",
                "tcp": 15.0 if h == "10.0.0.5" else "нет ответа за 5 с"}):
            d = self.run_diag([self.lan, self.vpn])
        v = " ".join(d["verdict"])
        self.assertIn("RDP-серверы недоступны: 10.0.0.6:3389", v)
        self.assertIn("Туннель при этом работает", v)

    def test_rdp_drops_last_day(self):
        evs = [{"time": "2026-10-13T10:00:00.0000000+03:00", "id": 1026, "reason": 2308,
                "reason_text": winsys.RDP_DISCONNECT_REASON[2308]},
               {"time": "2026-10-13T11:00:00.0000000+03:00", "id": 1026, "reason": 1,
                "reason_text": winsys.RDP_DISCONNECT_REASON[1]}]
        with mock.patch.object(winsys, "rdp_client_events", return_value=evs):
            d = self.run_diag([self.lan, self.vpn])
        c = next(c for c in d["checks"] if c["name"] == "Обрывы за сутки")
        self.assertEqual(c["status"], "warn")
        self.assertTrue(c["summary"].startswith("1: соединение потеряно"))

    def test_vpn_connection_ignores_proxy_and_finds_client(self):
        srv = {"name": "ztn", "host": "vpng.example.ru", "port": 443, "proto": "tcp"}
        dns_ips = ["198.51.100.1", "198.51.100.2"]
        proxy = {"remote": "198.51.100.1", "rport": 443, "process": "sing-box",
                 "path": r"C:\Happ\sing-box.exe"}
        links = {"tcp": [proxy], "routes": []}
        self.assertIsNone(diagnose.vpn_connection(links, dns_ips, srv, self.cfg))
        client = {"remote": "203.0.113.7", "rport": 443, "process": "ztnsvc",
                  "path": r"C:\Program Files\Security Code\Continent ZTN\ztnsvc.exe"}
        links["tcp"].append(client)
        st, text, used, _ = diagnose.vpn_connection(links, dns_ips, srv, self.cfg)
        self.assertEqual(used, ["203.0.113.7"])
        self.assertEqual(st, diagnose.WARN)
        self.assertIn("нет в ответе DNS", text)

    def test_vpn_connection_first_connected(self):
        srv = {"name": "ztn", "host": "vpng.example.ru", "port": 443, "proto": "tcp"}
        p = r"C:\Program Files\Security Code\Continent ZTN\ztn.exe"
        links = {"tcp": [
            {"remote": "203.0.113.2", "rport": 443, "process": "ztn", "path": p,
             "state": "Established", "created": "2026-10-14T10:05:00.0000000+03:00"},
            {"remote": "203.0.113.1", "rport": 443, "process": "ztn", "path": p,
             "state": "Established", "created": "2026-10-14T10:00:00.0000000+03:00"}],
            "routes": []}
        st, text, used, _ = diagnose.vpn_connection(links, ["203.0.113.1", "203.0.113.2"],
                                                    srv, self.cfg)
        self.assertEqual(used[0], "203.0.113.1")
        self.assertIn("(с 10:00:00)", text)
        self.assertIn("первым подключился 203.0.113.1", text)

    def test_vpn_connection_via_local_proxy(self):
        srv = {"name": "ztn", "host": "vpng.example.ru", "port": 443, "proto": "tcp"}
        p = r"C:\Program Files\Security Code\Continent ZTN\ztn.exe"
        links = {"tcp": [
            {"remote": "127.0.0.1", "rport": 10808, "process": "ztn", "path": p},
            {"remote": "198.51.100.2", "rport": 443, "process": "sing-box",
             "created": "2026-10-14T10:05:00"},
            {"remote": "198.51.100.1", "rport": 443, "process": "sing-box",
             "created": "2026-10-14T10:00:00"},
            {"remote": "8.8.8.8", "rport": 443, "process": "sing-box"}], "routes": []}
        st, text, used, _ = diagnose.vpn_connection(
            links, ["198.51.100.1", "198.51.100.2"], srv, self.cfg)
        self.assertEqual(st, diagnose.OK)
        self.assertEqual(used, ["198.51.100.1", "198.51.100.2"])
        self.assertIn("через локальный прокси 127.0.0.1:10808", text)
        self.assertIn("первым - 198.51.100.1", text)
        self.assertNotIn("нет в ответе DNS", text)

    def test_continent_config_servers(self):
        data = {"profiles": [{"name": "Работа", "server": "vpn-a.example.ru:8443",
                              "backup": ["https://203.0.113.9/ztn"]},
                             {"gateway": {"address": "198.51.100.4", "port": 4433}}],
                "log": "client.log", "update": "https://securitycode.ru/x"}
        self.assertEqual(continent.servers_from_config(data), [
            {"host": "vpn-a.example.ru", "port": 8443}, {"host": "203.0.113.9", "port": 443},
            {"host": "198.51.100.4", "port": 4433}])
        cont = {"install": r"C:\Program Files\Security Code\Continent ZTN Client",
                "servers": [{"host": "203.0.113.9", "port": 443}], "config_error": None,
                "log_dirs": [], "collector": r"C:\x\LogCollector.exe"}
        d = self.run_diag([self.lan, self.vpn], cont=cont)
        names = [c["name"] for c in d["checks"]]
        self.assertIn("Континент: клиент", names)
        self.assertTrue(any("203.0.113.9:443" in n for n in names))

    def test_continent_profile_order_and_proxy(self):
        data = {"profiles": [{"name": "Работа", "profileType": "local", "connections": [
            {"host": "vpn-a.example.ru", "note": "", "tcpPort": 443, "udpPort": 4433},
            {"host": "203.0.113.9", "note": "", "tcpPort": 8443, "udpPort": 4433}]}]}
        prof = continent.profiles_from_data(data)
        self.assertEqual([(x["host"], x["port"]) for x in prof[0]["servers"]],
                         [("vpn-a.example.ru", 443), ("203.0.113.9", 8443)])
        self.assertEqual(continent.servers_from_config(data)[1],
                         {"host": "203.0.113.9", "port": 8443})
        cont = {"install": r"C:\x", "servers": [], "config_error": None, "log_dirs": [],
                "collector": None, "profiles": prof}
        with mock.patch.object(winsys, "system_proxy", return_value={
                "enabled": True, "server": "127.0.0.1:10809", "pac": ""}):
            d = self.run_diag([self.lan, self.vpn], cont=cont)
        c = {c["name"]: c for c in d["checks"]}
        self.assertIn("1) vpn-a.example.ru:443, 2) 203.0.113.9:8443",
                      c["Континент: профиль «Работа»"]["summary"])
        self.assertEqual(c["Системный прокси"]["status"], "warn")

    def test_continent_never_keeps_secrets(self):
        with tempfile.TemporaryDirectory() as d:
            prof = os.path.join(d, "profiles.json")
            with open(prof, "w", encoding="utf-8") as f:
                json.dump({"name": "Работа", "password": "secret1", "passwordEncrypted": True,
                           "login": "user", "containerPassword": "secret2",
                           "connections": [{"host": "vpn.example.ru", "tcpPort": 443}]}, f)
            for n in ("client.log", "password.txt", "keys.log"):
                open(os.path.join(d, n), "w").close()
            data = continent.load_json_safe(prof)
            self.assertNotIn("secret", json.dumps(data))
            self.assertEqual(data["connections"][0]["host"], "vpn.example.ru")
            with mock.patch.object(continent, "log_dirs", return_value=[d]):
                names = [os.path.basename(f) for f in continent.log_files()]
        self.assertEqual(names, ["client.log"])

    def test_vpn_tls_differs_between_ips(self):
        self.cfg["vpn"] = [{"name": "ztn", "host": "vpng.example.ru", "port": 443,
                            "proto": "tcp"}]
        tls = {"198.51.100.2": {"ok": True, "version": "TLSv1.3", "subject": "cdn.example.com",
                                "issuer": "R3", "names": ["cdn.example.com"]}}
        with mock.patch.object(probes, "resolve_all",
                               return_value=(["198.51.100.1", "198.51.100.2"], 3.0)):
            d = self.run_diag([self.lan, self.vpn], tls=tls)
        c = {c["name"]: c for c in d["checks"]}
        self.assertIn("выдан не на vpng.example.ru", c["ztn → 198.51.100.2:443/tcp"]["summary"])
        self.assertEqual(c["ztn → 198.51.100.2:443/tcp"]["status"], "warn")
        self.assertIn("TLS: handshake failure", c["ztn → 198.51.100.1:443/tcp"]["summary"])
        self.assertIn("отвечают на TLS по-разному", " ".join(d["verdict"]))

    def test_vpn_connection_from_host_route(self):
        srv = {"name": "ztn", "host": "vpng.example.ru", "port": 443, "proto": "tcp"}
        links = {"tcp": [], "routes": [{"prefix": "8.8.4.4/32", "nexthop": "192.168.1.1"},
                                       {"prefix": "10.1.1.1/32", "nexthop": "10.0.0.1"}]}
        st, text, used, _ = diagnose.vpn_connection(links, ["1.2.3.4"], srv, self.cfg)
        self.assertEqual(used, ["8.8.4.4"])
        self.assertIn("отдельные маршруты", text)

    def test_vpn_server_with_two_ips(self):
        self.cfg["vpn"] = [{"name": "ztn", "host": "vpng.example.ru", "port": 443,
                            "proto": "tcp"}]
        links = {"tcp": [{"remote": "5.5.5.2", "rport": 443, "procid": 7,
                          "process": "ContinentClient"}], "routes": []}
        with mock.patch.object(probes, "resolve_all",
                               return_value=(["5.5.5.1", "5.5.5.2"], 12.0)), \
                mock.patch.object(winsys, "network_links", return_value=links):
            d = self.run_diag([self.lan, self.vpn], tcp=lambda ip, port, timeout=5:
                              (True, 20.0) if ip == "5.5.5.2" else (False, "нет ответа"))
        names = [c["name"] for c in d["checks"]]
        self.assertIn("ztn → 5.5.5.1:443/tcp", names)
        self.assertIn("ztn → 5.5.5.2:443/tcp", names)
        self.assertEqual(d["vpn_connected"], {"ztn": ["5.5.5.2"]})
        v = " ".join(d["verdict"])
        self.assertIn("VPN-клиент подключён к ztn → 5.5.5.2.", v)
        self.assertIn("У ztn недоступен адрес 5.5.5.1", v)
        conn = next(c for c in d["checks"] if c["name"] == "ztn: подключение")
        self.assertIn("ContinentClient", conn["summary"])

    def test_vpn_connection_found_by_host_route(self):
        self.cfg["vpn"] = [{"name": "ztn", "host": "vpng.example.ru", "port": 443,
                            "proto": "tcp"}]
        links = {"tcp": [], "routes": [{"prefix": "5.5.5.1/32", "ifindex": 5,
                                        "nexthop": "192.168.1.1"}]}
        with mock.patch.object(probes, "resolve_all",
                               return_value=(["5.5.5.1", "5.5.5.2"], 12.0)), \
                mock.patch.object(winsys, "network_links", return_value=links):
            d = self.run_diag([self.lan, self.vpn])
        self.assertEqual(d["vpn_connected"], {"ztn": ["5.5.5.1"]})

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

    def test_readable_report_in_folder(self):
        d = self.run_diag([self.lan, self.vpn])
        events = [{"time": "2026-10-14T10:00:00", "level": "fail",
                   "text": "туннель «Continent» пропал\n    подробности"}]
        with tempfile.TemporaryDirectory() as tmp:
            folder = os.path.join(tmp, "Отчёты")
            os.makedirs(folder)
            with open(os.path.join(folder, "Мониторинг 2026-10-14 09-00.txt"), "w",
                      encoding="utf-8") as f:
                f.write("10:00:00 XX туннель пропал\n")
            with mock.patch.object(winsys, "system_dumps", return_value={}), \
                    mock.patch("netdiag.report.data_dir", return_value=tmp):
                path = report.build_zip(d, self.cfg, folder=folder, events=events,
                                        monitor_summary="мониторинг 5 мин")
            import zipfile
            names = zipfile.ZipFile(path).namelist()
            self.assertTrue(os.path.basename(path).startswith("Отчёт "))
            with open(path[:-4] + ".html", encoding="utf-8") as f:
                page = f.read()
        self.assertIn("Отчёт.html", names)
        self.assertIn("мониторинг/Мониторинг 2026-10-14 09-00.txt", names)
        self.assertIn("Итог", page)
        self.assertIn("туннель «Continent» пропал<br>", page)
        self.assertIn("мониторинг 5 мин", page)


class LiveTest(unittest.TestCase):
    def setUp(self):
        self.cfg = config.load(os.devnull + "-missing")
        self.cfg["other_vpn"] = ["happ"]

    def test_rdp_transport(self):
        ev = lambda i, t: {"id": i, "time": "2026-10-14T13:%s.0+03:00" % t}
        self.assertEqual(live.rdp_transport([ev(1024, "00:00"), ev(1103, "00:02")])[0],
                         "UDP (с 13:00:02), управление по TCP")
        text, st = live.rdp_transport([ev(1024, "00:00"), ev(1103, "00:02"), ev(1105, "05:00")])
        self.assertEqual((text, st), ("TCP: UDP-канал разорван в 13:05:00", "warn"))
        # старый сеанс с UDP, новый - без событий UDP
        self.assertEqual(live.rdp_transport([ev(1024, "00:00"), ev(1103, "00:02"),
                                             ev(1024, "10:00"), ev(1102, "10:01")])[0],
                         "TCP: UDP-канал не установился")
        self.assertIn("UDP", live.rdp_transport([], udp_socket=True)[0])
        self.assertEqual(live.rdp_transport(None, udp_socket=False)[0], "TCP")

    def test_read_rows(self):
        lan = adapter("Wi-Fi", ["192.168.100.5/24"], gateway=["192.168.100.12"], index=5)
        vpn = adapter("Подключение по локальной сети", ["10.61.207.130/32"], iftype=53, index=9,
                      desc="Continent TLS Adapter")
        happ = adapter("happ-tun", ["172.19.0.1/30"], iftype=53, index=12, desc="sing-box TUN")
        conns = [{"remote": "10.61.220.15", "rport": 3389, "lport": 50000, "pid": 7,
                  "process": "mstsc"},
                 {"remote": "127.0.0.1", "rport": 10808, "lport": 50001, "pid": 8,
                  "process": "VpnService",
                  "path": r"C:\Program Files\Security Code\Continent ZTN Client\VpnService.exe"}]
        info = live.Info(self.cfg)
        info.ext = ("178.176.250.130", 1000)
        evs = [{"id": 1024, "time": "2026-10-14T13:00:00"}, {"id": 1103, "time": "2026-10-14T13:00:02"}]
        with mock.patch.object(winsys, "rdp_client_events", return_value=evs):
            rows, key = info.read([lan, vpn, happ], conns, udp={7}, now=1030)
        d = {r[0]: (r[1], r[2]) for r in rows}
        self.assertEqual(d["VPN"][0], "подключён: Континент, через локальный прокси "
                                      "127.0.0.1:10808")
        info.vpn_ips = {"109.70.24.115"}
        conns.append({"remote": "109.70.24.115", "rport": 443, "lport": 50002, "pid": 9,
                      "process": "sing-box"})
        rows2, _ = info.read([lan, vpn, happ], conns, udp={7}, now=1030)
        self.assertEqual(rows2[0][1], "подключён: Континент, сервер 109.70.24.115:443 "
                                      "через прокси sing-box")
        self.assertIn("happ-tun", d["Другой VPN"][0])
        self.assertTrue(d["Внутренний IP"][0].startswith("10.61.207.130"))
        self.assertTrue(d["Локальный IP"][0].startswith("192.168.100.5"))
        self.assertEqual(d["Внешний IP"][0], "178.176.250.130  (проверен 30 с назад)")
        self.assertEqual(d["RDP"], ("подключён к 10.61.220.15:3389 (mstsc, 0 с)", "ok"))
        self.assertTrue(d["Протокол RDP"][0].startswith("UDP"))
        self.assertFalse(info.want_external(key, 1031) and info.ext_key == key)


class SessionTest(unittest.TestCase):
    EVS = [
        {"time": "2026-10-14T12:00:00.1+03:00", "id": 21, "props": ["CORP\\ivan", "2", "10.61.30.91"]},
        {"time": "2026-10-14T12:15:00.1+03:00", "id": 4800, "props": []},
        {"time": "2026-10-14T12:15:40.1+03:00", "id": 24, "props": ["CORP\\ivan", "2", "10.61.30.91"]},
        {"time": "2026-10-14T12:15:40.2+03:00", "id": 40, "props": ["2", "0"]},
        {"time": "2026-10-14T13:00:00.1+03:00", "id": 24, "props": ["CORP\\ivan", "3", "LOCAL"]},
        {"time": "2026-10-14T14:00:00.1+03:00", "id": 24, "props": ["CORP\\ivan", "2", "10.61.30.91"]},
        {"time": "2026-10-14T14:00:00.2+03:00", "id": 40, "props": ["2", "3"]},
    ]

    def evs(self):
        return [session.parse_event(dict(e)) for e in self.EVS]

    def test_correlate_lock_then_disconnect(self):
        c = session.correlate(self.evs())
        self.assertEqual(len(c), 2)  # LOCAL пропущен
        self.assertEqual((c[0]["after"], c[0]["gap"], c[0]["reason"]),
                         ("компьютер заблокирован", 40, 0))
        self.assertIsNone(c[1]["after"])
        self.assertEqual(c[1]["reason"], 3)

    def test_summarize_and_timers(self):
        st, text = session.summarize({}, {"events": self.evs(), "denied": ["Security"]})
        self.assertEqual(st, "warn")
        self.assertIn("сразу после блокировки, заставки или сна: 1 (12:15:40 через 40 с", text)
        self.assertIn("по лимиту простоя сервера: 1", text)
        self.assertIn("от имени администратора", text)
        lines = session.describe_timers({"lock_inactivity": 900, "screensaver_active": "1",
                                         "screensaver_timeout": 600, "screensaver_secure": "1",
                                         "rdp_idle": 3600, "sleep_ac": 1800})
        text = "; ".join(t for t, _ in lines)
        self.assertIn("блокировка по простою (политика): через 15 мин", text)
        self.assertIn("заставка через 10 мин, с блокировкой", text)
        self.assertIn("лимит простоя сеанса RDP: через 1 ч", text)
        self.assertIn("сон через 30 мин", text)
        self.assertTrue(any(imp for _, imp in lines))


class MonitorTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.patch = mock.patch.object(monitor, "logs_dir", return_value=self.tmp.name)
        self.patch.start()
        cfg = config.load(os.devnull + "-missing")
        self.events = []
        self.m = monitor.Monitor(cfg, interval=2, on_event=lambda ev, line: self.events.append(ev))
        self.m.state = {"tunnels": {"Continent": "10.1.1.1"}, "physical": {}, "other_vpn": []}

    def tearDown(self):
        self.patch.stop()
        self.tmp.cleanup()

    def test_probe_goes_down_after_two_fails_and_back(self):
        p = monitor.Probe("internal", "туннель 10.0.0.1", "10.0.0.1")
        self.m.probes = [p]
        self.m._update_probe(p, True, 10, 100)
        self.m._update_probe(p, False, None, 102)
        self.assertEqual(self.events, [])  # одна потеря - ещё не обрыв
        self.m._update_probe(p, False, None, 104)
        self.assertEqual(self.events[-1]["level"], "fail")
        self.m._update_probe(p, True, 10, 110)
        self.assertIn("снова отвечает", self.events[-1]["text"])
        self.assertEqual(p.drops, 1)
        self.assertTrue(os.path.exists(self.m.text_path))

    def test_tunnel_lost_event(self):
        old = {"tunnels": {"Continent": "10.1.1.1"}, "physical": {}, "other_vpn": []}
        new = {"tunnels": {}, "physical": {}, "other_vpn": ["happ-tun"]}
        self.m._diff_snapshot(old, new)
        texts = " ".join(e["text"] for e in self.events)
        self.assertIn("туннель «Continent» пропал", texts)
        self.assertIn("другой VPN: выключен → happ-tun", texts)

    def test_vpn_dns_and_connected_ip_changes(self):
        self.m.vpn_list = self.m.cfg["vpn"] = [{"name": "Континент", "host": "vpn.example", "port": 443,
                              "proto": "tcp"}]
        links = {"tcp": [{"remote": "192.0.2.1", "rport": 443, "process": "ztn"}], "routes": []}
        dns = {"ips": ["192.0.2.1", "192.0.2.2"]}
        with mock.patch.object(monitor.probes, "resolve_all", lambda h: (dns["ips"], 5.0)), \
                mock.patch.object(monitor.winsys, "network_links", lambda: links):
            self.m._apply_vpn(self.m._read_vpn())
            texts = [e["text"] for e in self.events]
            self.assertIn("Континент: DNS vpn.example → 192.0.2.1, 192.0.2.2", texts)
            self.assertIn("Континент: клиент подключён к 192.0.2.1", texts)
            n = len(self.events)
            self.m._apply_vpn(self.m._read_vpn())
            self.assertEqual(len(self.events), n)  # ничего не изменилось - тишина
            links["tcp"][0]["remote"] = "192.0.2.2"
            dns["ips"] = ["192.0.2.2"]
            self.m._apply_vpn(self.m._read_vpn())
        texts = " ".join(e["text"] for e in self.events[n:])
        self.assertIn("DNS vpn.example изменился: 192.0.2.1, 192.0.2.2 → 192.0.2.2", texts)
        self.assertIn("переключился с 192.0.2.1 на 192.0.2.2", texts)

    def test_disconnect_explained_by_vpn_reconnect(self):
        p = monitor.Probe("internal", "туннель 10.0.0.1", "10.0.0.1")
        self.m.probes = [p]
        base = {"probes": {p.name: True}, "tunnel": True, "other_vpn": []}
        self.m.history.extend([dict(base, t=100, vpn={"К": ["192.0.2.1"]}),
                               dict(base, t=102, vpn={"К": ["192.0.2.2"]})])
        self.assertIn("переподключался", self.m.explain_disconnect(103))

    def test_wifi_roaming(self):
        self.m._diff_wifi({"bssid": "aa", "signal_pct": 80}, {"bssid": "bb", "signal_pct": 35})
        texts = " ".join(e["text"] for e in self.events)
        self.assertIn("другую точку", texts)
        self.assertIn("слабый сигнал", texts)

    def _hist(self, **over):
        self.m.probes = [monitor.Probe("gateway", "роутер", "1"),
                         monitor.Probe("internet", "интернет", "2"),
                         monitor.Probe("internal", "туннель", "3")]
        base = {"probes": {"роутер": True, "интернет": True, "туннель": True},
                "tunnel": True, "other_vpn": [], "wifi": "aa"}
        self.m.history.clear()
        for i in range(10):
            t = dict(base, t=1000 + i * 2, probes=dict(base["probes"]))
            if i == 8:
                for k, v in over.items():
                    if k in t["probes"]:
                        t["probes"][k] = v
                    else:
                        t[k] = v
            self.m.history.append(t)
        return self.m.explain_disconnect(at=1018)

    def test_explain_disconnect(self):
        self.assertIn("туннель VPN", self._hist(tunnel=False))
        self.assertIn("роутер", self._hist(**{"роутер": False}))
        self.assertIn("провайдера", self._hist(**{"интернет": False}))
        self.assertIn("трафик через туннель не шёл", self._hist(**{"туннель": False}))
        self.assertIn("другой VPN", self._hist(other_vpn=["happ-tun"]))
        self.assertIn("обрыв на стороне RDP", self._hist())

    def test_rdp_disconnect_from_log(self):
        self._hist(**{"туннель": False})
        ev = {"time": None, "id": 1026, "props": ["2308"], "reason": 2308,
              "reason_text": winsys.RDP_DISCONNECT_REASON[2308]}
        with mock.patch.object(winsys, "rdp_client_events", return_value=[ev]), \
                mock.patch.object(self.m, "explain_disconnect", return_value="X"):
            self.m._check_rdp_log(set())
        self.assertIn("сеанс отключён", self.events[-1]["text"])
        self.assertIn("2308", self.events[-1]["text"])

    def test_rdp_drop_after_same_idle(self):
        B = 1760000000
        self.m.history.extend([{"t": B + 100, "probes": {}, "last_input": B},
                               {"t": B + 1000, "probes": {}, "last_input": B + 1000},
                               {"t": B + 2000, "probes": {}, "last_input": B + 1300}])
        with mock.patch.object(self.m, "_route_of", return_value=None):
            t1 = self.m.describe_disconnect({"id": 1026, "reason": 2308,
                                             "time": datetime.datetime.fromtimestamp(B + 900).isoformat()})
            t2 = self.m.describe_disconnect({"id": 1026, "reason": 2308,
                                             "time": datetime.datetime.fromtimestamp(B + 1920).isoformat()})
        self.assertIn("не работали 15 мин", t1)
        self.assertNotIn("одинакового простоя", t1)
        self.assertIn("2-й раз после одинакового простоя", t2)

    def test_session_lock_then_disconnect_logged(self):
        evs = [session.parse_event(dict(e)) for e in SessionTest.EVS[:4]]
        self.m._check_session_events(set(), evs)
        texts = [e["text"] for e in self.events]
        self.assertTrue(any("компьютер заблокирован" in t for t in texts))
        warn = [e for e in self.events if e["level"] == "warn"]
        self.assertIn("через 40 с после «компьютер заблокирован»", warn[0]["text"])

    def test_rdp_disconnect_while_session_alive_is_not_error(self):
        evs = [{"time": None, "id": 1105, "props": []},
               {"time": None, "id": 1026, "props": ["263"], "reason": 263,
                "reason_text": winsys.RDP_DISCONNECT_REASON[263]}]
        conn = {"remote": "10.61.220.15", "rport": 3389, "lport": 50000, "pid": 7,
                "process": "mstsc", "state": "established"}
        with mock.patch.object(winsys, "rdp_client_events", return_value=evs), \
                mock.patch.object(monitor.ad, "tcp_connections", return_value=[conn]):
            self.m._check_rdp_log(set())
        self.assertEqual([e["level"] for e in self.events], ["info", "info"])
        self.assertIn("Сеанс продолжается", self.events[-1]["text"])
        self.assertIn("mstsc → 10.61.220.15:3389", self.events[-1]["text"])

    @unittest.skipUnless(sysutil.IS_WINDOWS, "только Windows")
    def test_tcp_connections_windows(self):
        conns = monitor.ad.tcp_connections()
        self.assertIsInstance(conns, list)

    def test_vpn_client_tries_first_ip_then_second(self):
        self.m.vpn_list = self.m.cfg["vpn"] = [{"name": "К", "host": "vpn.example", "port": 443, "proto": "tcp"}]
        path = r"C:\Program Files\Security Code\Continent ZTN\ztn.exe"

        def c(ip, lport, state):
            return {"remote": ip, "rport": 443, "lport": lport, "pid": 5, "process": "ztn",
                    "path": path, "state": state}
        self.m._check_vpn_tcp([], 100)
        self.m._check_vpn_tcp([c("203.0.113.1", 50001, "syn_sent")], 102)
        self.m._check_vpn_tcp([c("203.0.113.2", 50002, "syn_sent")], 125)
        self.m._check_vpn_tcp([c("203.0.113.2", 50002, "established")], 127)
        texts = [e["text"] for e in self.events]
        self.assertIn("пробует подключиться к 203.0.113.1:443", texts[0])
        self.assertIn("203.0.113.1:443 не ответил", " ".join(texts))
        self.assertIn("подключился к 203.0.113.2:443 (ответ через 2 с)", texts[-1])

    def test_rdp_event_props_name_value(self):
        e = winsys.parse_rdp_event({"id": 1026, "props": ["Disconnect Reason", "2308"]})
        self.assertEqual(e["reason"], 2308)
        self.assertIn("соединение потеряно", e["reason_text"])
        e = winsys.parse_rdp_event({"id": 1024, "props": ["Server Name", "srv.corp"]})
        self.assertEqual(e["server"], "srv.corp")
        self.assertEqual(winsys.parse_rdp_event({"id": 1026, "props": ["3"]})["reason"], 3)

    def test_rdp_tcp_watch_and_disconnect_details(self):
        B = 1760000000  # реальное время: на Windows timestamp() около 1970 года падает
        conn = {"remote": "10.61.220.15", "rport": 3389, "lport": 50000, "pid": 7,
                "process": "mstsc"}
        other = {"remote": "1.1.1.1", "rport": 443, "lport": 50001, "pid": 8,
                 "process": "chrome"}
        with mock.patch.object(monitor.ad, "tcp_connections", side_effect=[
                [conn, other], [dict(conn)], [other]]):
            self.assertEqual(self.m._check_rdp_tcp(B + 1000), 1)
            self.m._check_rdp_tcp(B + 1002)
            self.assertEqual(self.m._check_rdp_tcp(B + 1004), 0)
        self.assertIn("закрыто", self.events[-1]["text"])
        self.m.rdp_session = {"server": "10.61.220.15", "t": B + 400}
        self.m.rdp_udp_lost = B + 990
        self.m.history.append({"t": B + 1000, "probes": {}, "tunnel": True, "other_vpn": []})
        with mock.patch.object(self.m, "_route_of", return_value="Continent"):
            text = self.m.describe_disconnect({"id": 1026, "reason": 2308,
                                               "time": datetime.datetime.fromtimestamp(
                                                   B + 1005).isoformat()})
        self.assertIn("длился 10 мин 5 с", text)
        self.assertIn("UDP-канал RDP разорвался", text)
        self.assertIn("TCP-соединение mstsc → 10.61.220.15:3389 закрылось", text)
        self.assertIn("через «Continent»", text)
        self.assertIn("по неактивности", text)

    def test_event_epoch(self):
        self.assertIsNotNone(monitor._event_epoch("2026-10-13T18:22:54.1234567+03:00"))
        self.assertIsNone(monitor._event_epoch("bad"))


if __name__ == "__main__":
    unittest.main()
