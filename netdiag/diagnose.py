# -*- coding: utf-8 -*-
"""Полная проверка сети и VPN: сбор, проверки, итоговый вердикт.

Проверки идут по уровням:
  1. локальная сеть (адаптер, адрес, шлюз);
  2. интернет под VPN (ping, DNS, внешний IP);
  3. VPN-серверы из настроек (имя, порт, ping, MTU) - все одновременно;
  4. туннель (адаптер 10.x, маршруты, внутренние адреса, счётчики трафика);
  5. готовность ПК принимать RDP через туннель.
"""

import collections
import concurrent.futures
import datetime
import ipaddress
import platform
import socket
import time

from . import __version__, adapters as ad, probes, winsys

OK, WARN, FAIL, INFO = "ok", "warn", "fail", "info"


class Report:
    def __init__(self, progress=None):
        self.checks = []
        self.verdict = []
        self.progress = progress

    def add(self, group, name, status, summary, **details):
        item = {"group": group, "name": name, "status": status,
                "summary": summary, "details": details}
        self.checks.append(item)
        if self.progress:
            try:
                self.progress(item)
            except Exception:
                pass
        return item


# --------------------------------------------------------------------------
# Классификация адаптеров
# --------------------------------------------------------------------------
def _match_client(adapter, patterns):
    text = ("%s %s" % (adapter.get("name", ""), adapter.get("description", ""))).lower()
    for client, words in patterns.items():
        if any(w.lower() in text for w in words):
            return client
    return None


def _other_vpn(adapter_list, cfg):
    """Включённые адаптеры посторонних VPN (Happ/sing-box, WireGuard и т.п.)."""
    res = []
    for a in adapter_list:
        if not a["up"] or a.get("loopback") or _match_client(a, cfg["patterns"]):
            continue
        text = ("%s %s" % (a.get("name", ""), a.get("description", ""))).lower()
        if any(w.lower() in text for w in cfg.get("other_vpn", [])):
            res.append(a)
    return res


def vpn_connection(links, ips, srv, cfg):
    """К какому адресу подключён VPN-клиент: (статус, текст, адреса, данные) или None.

    Сначала ищутся TCP-соединения самого клиента (по имени процесса и пути
    к программе) - с любыми адресами, даже если DNS отдаёт другие. Соединения
    прокси других VPN (sing-box и т.п.) не учитываются: через них идут и наши
    собственные проверки. Потом - соединения прочих программ и маршруты /32.
    """
    if links is None:
        return None
    patterns = [w for ws in cfg["patterns"].values() for w in ws]
    own = winsys.client_links(links, patterns)["client"]
    port = srv["port"] if srv["proto"] == "tcp" else None
    if own:
        eps, used = [], []
        for c in own:
            ep = "%s:%s" % (c["remote"], c["rport"])
            if ep not in eps:
                eps.append(ep)
            if c["remote"] not in used:
                used.append(c["remote"])
        text = "клиент (процесс %s) подключён к %s" % (own[0].get("process") or "?", ", ".join(eps))
        foreign = [ip for ip in used if ip not in ips]
        if foreign and not set(used) & set(ips):
            text += "; этих адресов нет в ответе DNS для %s: DNS сейчас отдаёт другие " \
                    "адреса (возможно, отвечает через другой VPN)" % srv["host"]
            return WARN, text, used, {"client_tcp": own}
        return OK, text, used, {"client_tcp": own}
    sl = winsys.server_links(links, ips, port)
    used = []
    for c in sl["tcp"]:
        if c["remote"] not in used:
            used.append(c["remote"])
    if used:
        proc = sl["tcp"][0].get("process")
        return OK, "клиент подключён к %s (TCP-соединение%s)" % (
            ", ".join(used), " процесса %s" % proc if proc else ""), used, {"links": sl}
    used = [rt["ip"] for rt in sl["routes"]]
    if used:
        return OK, "клиент подключён к %s (отдельный маршрут к серверу)" % ", ".join(used), \
            used, {"links": sl}
    # Адреса не из DNS: VPN-клиенты ставят маршрут /32 к своему серверу через шлюз
    # провайдера, чтобы соединение с сервером не ушло в собственный туннель.
    routes = []
    for rt in links.get("routes", []):
        ip = (rt.get("prefix") or "").split("/")[0]
        hop = rt.get("nexthop") or ""
        if _is_public(ip) and hop not in ("", "0.0.0.0") and ip not in routes:
            routes.append(ip)
    if routes:
        return WARN, "соединений с адресами из DNS нет, но есть отдельные маршруты к внешним " \
            "адресам через шлюз: %s - вероятно, к ним и подключён клиент; этих адресов нет " \
            "в ответе DNS для %s" % (", ".join(routes), srv["host"]), routes, \
            {"host_routes": routes}
    others = []
    for c in links.get("tcp", []):
        if (port is None or c.get("rport") == port) and _is_public(c.get("remote")) \
                and not winsys._proc_matches(c, winsys.PROXY_PROCS + BROWSERS):
            ep = "%s → %s" % (c.get("process") or "?", c["remote"])
            if ep not in others:
                others.append(ep)
    if others:
        return INFO, "соединений клиента не найдено; другие программы на порт %s: %s" % (
            port, ", ".join(others[:8])), [], {}
    return None


BROWSERS = ("chrome", "msedge", "firefox", "opera", "yandex", "browser", "brave", "vivaldi",
            "telegram", "discord", "steam", "onedrive", "teams", "outlook", "searchhost",
            "svchost", "msedgewebview2", "widgets")


def _is_public(ip):
    try:
        a = ipaddress.IPv4Address(ip)
    except (ValueError, TypeError):
        return False
    return a.is_global


def classify(adapter_list, cfg):
    """Делит адаптеры на туннели VPN, локальные и установленные, но не поднятые VPN."""
    try:
        tnet = ipaddress.IPv4Network(cfg["tunnel_network"], strict=False)
    except ValueError:
        tnet = ipaddress.IPv4Network("10.0.0.0/8")

    tunnels, local, idle_vpn, lan_conflicts = [], [], [], []
    other = _other_vpn(adapter_list, cfg)
    for a in adapter_list:
        if a.get("loopback"):
            continue
        client = _match_client(a, cfg["patterns"])
        if not client and a in other:
            continue
        in_tnet = [ip for ip in ad.ipv4_addrs(a) if _in(ip, tnet)]
        if a["up"] and in_tnet and (client or a.get("iftype") not in (6, 71)):
            tunnels.append(dict(a, client=client or "VPN (не опознан)", tunnel_ip=in_tnet[0]))
        elif client:
            idle_vpn.append(dict(a, client=client))
        elif a["up"] and (a["ipv4"] or a["ipv6"]):
            local.append(a)
            if in_tnet:
                lan_conflicts.append(a)
    return tunnels, local, idle_vpn, lan_conflicts


VIRTUAL_WORDS = ("VirtualBox", "VMware", "Hyper-V", "vEthernet", "Host-Only")


def _is_virtual(adapter):
    """Адаптеры виртуальных машин: на связь с интернетом и VPN не влияют."""
    text = "%s %s" % (adapter.get("name", ""), adapter.get("description", ""))
    return any(w.lower() in text.lower() for w in VIRTUAL_WORDS)


def _vpn_ip_status(r, s):
    """Статус и описание проверки одного адреса VPN-сервера."""
    parts, st = [], OK
    if s["proto"] == "tcp":
        if r["tcp_ok"]:
            parts.append("порт открыт за %d мс" % r["tcp"])
        else:
            parts.append("порт %d: %s" % (s["port"], r["tcp"]))
            st = FAIL
    p = r["ping"]
    parts.append("ping " + _fmt_ping(p))
    if p["received"] and p["loss_pct"] >= 25 and st == OK:
        st = WARN
    if r.get("mtu"):
        parts.append("MTU %d" % r["mtu"])
        if r["mtu"] < 1400 and st == OK:
            st = WARN
    if s["proto"] == "udp" and not p["received"]:
        st = WARN  # UDP-порт проверить нельзя, а ping может быть закрыт
    return st, parts


def _probe_rdp(host, port):
    ip, err = probes.resolve4(host)
    if ip is None:
        return {"host": host, "ip": None, "dns_error": err}
    ok, info = probes.tcp_connect(ip, port, timeout=5)
    return {"host": host, "ip": ip, "port": port, "tcp_ok": ok, "tcp": info}


def _in(ip, net):
    try:
        return ipaddress.IPv4Address(ip) in net
    except ValueError:
        return False


def _fmt_ping(p):
    if not p["received"]:
        return "нет ответа (%s)" % ", ".join(p["errors"]) if p["errors"] else "нет ответа"
    s = "%d мс, потери %d%%" % (round(p["avg_ms"]), p["loss_pct"])
    if p["loss_pct"] and p["errors"]:
        s += " (%s)" % ", ".join(p["errors"])
    return s


def _ping_status(p):
    if not p["received"]:
        return FAIL
    return WARN if p["loss_pct"] >= 25 or p.get("avg_ms", 0) > 300 else OK


# --------------------------------------------------------------------------
# Отдельные проверки (выполняются параллельно)
# --------------------------------------------------------------------------
def _probe_host(host, count=4, mtu=False):
    """Имя -> IP, ping, при успехе - MTU пути."""
    ip, dns = probes.resolve4(host)
    res = {"host": host, "ip": ip}
    if ip is None:
        res["dns_error"] = dns
        return res
    res["dns_ms"] = round(dns, 1) if host != ip else None
    res["ping"] = probes.ping(ip, count=count)
    if mtu and res["ping"]["received"]:
        res["mtu"] = probes.find_mtu(ip)
    return res


def _probe_vpn_ip(ip, srv):
    res = {"ip": ip, "ping": probes.ping(ip, count=4)}
    if res["ping"]["received"]:
        res["mtu"] = probes.find_mtu(ip)
    if srv["proto"] == "tcp":
        res["tcp_ok"], res["tcp"] = probes.tcp_connect(ip, srv["port"])
    return res


def _probe_vpn_server(srv):
    """У имени сервера может быть несколько адресов - проверяем каждый отдельно."""
    ips, dns = probes.resolve_all(srv["host"])
    res = {"host": srv["host"], "ips": ips, "per_ip": {}}
    if not ips:
        res["dns_error"] = dns
        return res
    res["dns_ms"] = round(dns, 1) if ips != [srv["host"]] else None
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(ips)) as ex:
        futs = {ip: ex.submit(_probe_vpn_ip, ip, srv) for ip in ips}
        res["per_ip"] = {ip: f.result() for ip, f in futs.items()}
    return res


def run(cfg, progress=None):
    """Полная проверка. Возвращает словарь с данными, проверками и вердиктом."""
    t0 = time.time()
    rep = Report(progress)
    all_adapters = ad.get_adapters(include_down=True)
    tunnels, local, idle_vpn, lan_conflicts = classify(all_adapters, cfg)
    by_index = {a["index"]: a for a in all_adapters if a.get("index")}
    other_vpn = _other_vpn(all_adapters, cfg)
    other_index = {a["index"] for a in other_vpn}

    def via_other(ip):
        """Адаптер постороннего VPN, через который уйдёт пакет на ip, или None."""
        idx = ad.best_interface(ip) if other_index and ip else None
        return by_index.get(idx) if idx in other_index else None

    # Трафик туннеля до проверок: потом сравним, вернулось ли что-то
    stats_before = {t["index"]: ad.if_stats(t["index"]) for t in tunnels}

    pool = concurrent.futures.ThreadPoolExecutor(max_workers=24)
    gateways = sorted({g for a in local for g in a["gateway"] if ":" not in g})
    f_gw = {g: pool.submit(probes.ping, g, 4) for g in gateways}
    f_inet = {h: pool.submit(_probe_host, h) for h in cfg["internet"]}
    f_ext = pool.submit(probes.external_ip)
    f_vpn = {s["name"]: pool.submit(_probe_vpn_server, s) for s in cfg["vpn"]}
    internal = cfg["internal"] or _auto_internal(tunnels, cfg)
    f_int = {i["name"]: pool.submit(_probe_host, i["host"], 6, bool(tunnels))
             for i in internal}
    f_rdpt = [pool.submit(_probe_rdp, t["host"], t["port"]) for t in cfg.get("rdp_targets", [])]
    f_wifi = pool.submit(winsys.wifi_info)
    f_rdp = pool.submit(winsys.rdp_info) if cfg["rdp"] else None
    f_fw = pool.submit(winsys.firewall_info) if cfg["rdp"] else None
    f_dev = pool.submit(winsys.net_devices)
    f_links = pool.submit(winsys.network_links)
    f_rdplog = pool.submit(winsys.rdp_client_events, 24 * 60)

    # ---- 1. Локальная сеть ------------------------------------------------
    G = "Локальная сеть"
    physical = [a for a in local if a["ipv4"]]
    if not physical:
        down = [a["name"] for a in all_adapters
                if not a["up"] and not a.get("loopback") and a.get("iftype") in (6, 71)]
        rep.add(G, "Подключение", FAIL, "нет активного сетевого подключения",
                disconnected=down)
    for a in physical:
        ips = ad.ipv4_addrs(a)
        name = a["name"] if a["type"] in a["name"] else "%s (%s)" % (a["name"], a["type"])
        if all(ad.is_apipa(ip) for ip in ips):
            rep.add(G, name, FAIL, "адрес %s: DHCP не выдал адрес (роутер не ответил)" % ips[0],
                    adapter=a)
        elif not a["gateway"] and _is_virtual(a):
            rep.add(G, name, INFO, "%s, виртуальный адаптер (%s): на связь не влияет"
                    % (ips[0], a["description"]), adapter=a)
        elif not a["gateway"]:
            rep.add(G, name, WARN, "%s, нет шлюза: выхода в другие сети не будет" % ips[0],
                    adapter=a)
        else:
            rep.add(G, name, OK, "%s, шлюз %s, DNS %s" % (
                ", ".join(a["ipv4"]), ", ".join(a["gateway"]), ", ".join(a["dns"]) or "-"),
                adapter=a)
    for a in other_vpn:
        rep.add(G, "Другой VPN", INFO, "включён «%s» (%s)" % (a["name"], a["description"]),
                adapter=a["name"])
    for a in lan_conflicts:
        rep.add(G, "Конфликт адресов", WARN,
                "сеть «%s» использует %s: тот же диапазон, что у корпоративной сети. "
                "Часть трафика может уходить в эту сеть, а не в туннель"
                % (a["name"], ", ".join(a["ipv4"])), adapter=a["name"])

    wifi = f_wifi.result()
    if wifi:
        sig = wifi.get("signal_pct")
        st = OK if sig is None or sig >= 50 else (WARN if sig >= 30 else FAIL)
        rep.add(G, "Wi-Fi", st, "сеть «%s», сигнал %s%%, канал %s, %s" % (
            wifi.get("ssid"), sig if sig is not None else "?", wifi.get("channel", "?"),
            wifi.get("radio", "")), **wifi)

    gw_ok = None
    for g, f in f_gw.items():
        p = f.result()
        gw_ok = bool(gw_ok) or p["received"] > 0
        rep.add(G, "Роутер %s" % g, _ping_status(p), _fmt_ping(p), ping=p)

    # ---- 2. Интернет --------------------------------------------------------
    G = "Интернет"
    inet_ok, dns_fail = False, False
    for h, f in f_inet.items():
        r = f.result()
        if r["ip"] is None:
            dns_fail = True
            rep.add(G, h, FAIL, r["dns_error"], **r)
            continue
        p = r["ping"]
        inet_ok = inet_ok or p["received"] > 0
        extra = ", DNS %d мс" % r["dns_ms"] if r.get("dns_ms") else ""
        other = via_other(r["ip"])
        if other:
            extra += "; идёт через «%s», ответ может давать сам этот VPN" % other["name"]
        rep.add(G, h, _ping_status(p), _fmt_ping(p) + extra, **r)
    ext_ip, ext_err = f_ext.result()
    if ext_ip:
        inet_ok = True
        rep.add(G, "Внешний IP", OK, ext_ip, ip=ext_ip)
    else:
        rep.add(G, "Внешний IP", FAIL, "не получен", error=ext_err)

    # ---- 3. VPN-серверы -----------------------------------------------------
    G = "VPN-серверы"
    vpn_ok, vpn_fail, vpn_via_other = [], [], []
    if not cfg["vpn"]:
        rep.add(G, "Настройки", INFO, "серверы не заданы: добавьте их в раздел [vpn] файла ipinfo.ini")
    links = f_links.result()
    vpn_connected, vpn_bad_ips = {}, {}
    for s in cfg["vpn"]:
        r = f_vpn[s["name"]].result()
        if not r["ips"]:
            vpn_fail.append(s["name"])
            rep.add(G, "%s (%s)" % (s["name"], s["host"]), FAIL, r["dns_error"], **r)
            continue
        if r.get("dns_ms") is not None:
            rep.add(G, "%s: DNS" % s["name"], OK, "%s → %s (%d мс)" % (
                s["host"], ", ".join(r["ips"]), r["dns_ms"]), ips=r["ips"])
        good = []
        for ip in r["ips"]:
            st, parts = _vpn_ip_status(r["per_ip"][ip], s)
            other = via_other(ip)
            if other:
                vpn_via_other.append("%s через «%s»" % (s["name"], other["name"]))
                parts.append("подключение идёт через «%s»: на ping и порт может отвечать сам "
                             "этот VPN" % other["name"])
                if st == OK:
                    st = WARN
            if st != FAIL:
                good.append(ip)
            else:
                vpn_bad_ips.setdefault(s["name"], []).append(ip)
            rep.add(G, "%s → %s:%d/%s" % (s["name"], ip, s["port"], s["proto"]), st,
                    ", ".join(parts), **r["per_ip"][ip])
        (vpn_ok if good else vpn_fail).append(s["name"])

        # К какому из адресов реально подключён клиент
        line = vpn_connection(links, r["ips"], s, cfg)
        if line:
            st, text, used, extra = line
            if used:
                vpn_connected[s["name"]] = used
            if used and set(used) & set(vpn_bad_ips.get(s["name"], [])):
                st = WARN
            rep.add(G, "%s: подключение" % s["name"], st, text, **extra)
        elif links is not None and tunnels:
            rep.add(G, "%s: подключение" % s["name"], INFO,
                    "соединений клиента с адресами %s не найдено: клиент подключён к другому "
                    "серверу или по UDP" % ", ".join(r["ips"]))

    # ---- 4. Туннель ---------------------------------------------------------
    G = "Туннель"
    int_results = {i["name"]: f_int[i["name"]].result() for i in internal}
    stats_after = {t["index"]: ad.if_stats(t["index"]) for t in tunnels}
    tunnel_index = {t["index"] for t in tunnels}
    int_ok = int_total = 0

    devices = f_dev.result()
    device_problems = _check_vpn_devices(rep, G, devices, cfg) if not tunnels else []
    if not tunnels:
        if idle_vpn:
            rep.add(G, "Состояние", FAIL, "туннель не поднят. Установлено: %s" % ", ".join(
                sorted({"%s («%s», %s)" % (a["client"], a["name"], a["status"])
                        for a in idle_vpn})))
        else:
            rep.add(G, "Состояние", FAIL, "туннель не поднят: нет адаптера с адресом из %s"
                    % cfg["tunnel_network"])
    for t in tunnels:
        rep.add(G, t["client"], OK, "адаптер «%s», адрес %s, DNS %s, MTU %s" % (
            t["name"], ", ".join(t["ipv4"]), ", ".join(t["dns"]) or "-", t["mtu"] or "-"),
            adapter=t)

    for i in internal:
        r = int_results[i["name"]]
        label = "%s (%s)" % (i["name"], i["host"])
        if r["ip"] is None:
            rep.add(G, label, FAIL, r["dns_error"], **r)
            continue
        int_total += 1
        route_if = ad.best_interface(r["ip"])
        via = by_index.get(route_if)
        route = {"index": route_if, "name": via["name"] if via else None}
        if tunnels and route_if is not None and route_if not in tunnel_index:
            rep.add(G, label, FAIL, "пакеты уходят не в туннель, а в «%s»: конфликт маршрутов"
                    % (via["name"] if via else route_if), route=route, **r)
            continue
        p = r["ping"]
        ok = p["received"] > 0
        int_ok += ok
        s = _fmt_ping(p)
        if r.get("mtu"):
            s += ", MTU через туннель %d" % r["mtu"]
        st = _ping_status(p)
        if ok and r.get("mtu") and r["mtu"] < 1200:
            st = WARN
        rep.add(G, label, st, s, route=route, **r)

    traffic = {}
    for t in tunnels:
        b, a = stats_before.get(t["index"]), stats_after.get(t["index"])
        if not (a and b):
            continue
        d = {k: a[k] - b[k] for k in a}
        traffic[t["name"]] = {"before": b, "after": a, "delta": d}
        txt = "за время проверки отправлено %d байт, получено %d байт; всего с подключения " \
              "отправлено %s, получено %s" % (d["tx_bytes"], d["rx_bytes"],
                                            _mb(a["tx_bytes"]), _mb(a["rx_bytes"]))
        if a["rx_errors"] or a["tx_errors"] or a["rx_discards"]:
            txt += "; ошибки приёма %d, передачи %d, отброшено %d" % (
                a["rx_errors"], a["tx_errors"], a["rx_discards"])
        st = OK
        if int_total and d["tx_bytes"] > 0 and d["rx_bytes"] == 0:
            st = FAIL
            txt += ". Трафик уходит, но ничего не возвращается"
        rep.add(G, "Трафик «%s»" % t["name"], st, txt, **traffic[t["name"]])

    # ---- 5. RDP ---------------------------------------------------------------
    G = "RDP"
    rdp_out_ok, rdp_out_fail = [], []
    for t, f in zip(cfg.get("rdp_targets", []), f_rdpt):
        r = f.result()
        label = "%s:%d" % (t["host"], t["port"])
        if r["ip"] is None:
            rdp_out_fail.append(label)
            rep.add(G, label, FAIL, r["dns_error"], **r)
            continue
        idx = ad.best_interface(r["ip"])
        via = by_index.get(idx)
        route = " через «%s»" % via["name"] if via else ""
        if r["tcp_ok"]:
            rdp_out_ok.append(label)
            rep.add(G, label, OK, "порт RDP открыт за %d мс%s" % (r["tcp"], route), **r)
        else:
            rdp_out_fail.append(label)
            rep.add(G, label, FAIL, "%s%s" % (r["tcp"], route), **r)
    rdp_log = f_rdplog.result()
    drops = [e for e in rdp_log or [] if e.get("id") == 1026 and e.get("reason") not in (1, 2)]
    if drops:
        by_reason = collections.Counter(e.get("reason_text") for e in drops)
        rep.add(G, "Обрывы за сутки", WARN, "%d: %s; последний %s" % (
            len(drops), "; ".join("%s - %d" % kv for kv in by_reason.most_common()),
            drops[-1]["time"][:19].replace("T", " ")), events=drops)
    elif rdp_log is not None:
        rep.add(G, "Обрывы за сутки", OK, "по журналу клиента RDP обрывов не было")
    if not cfg.get("rdp_targets"):
        rep.add(G, "Настройки", INFO,
                "RDP-серверы не заданы: добавьте их в раздел [rdp] targets файла ipinfo.ini")
    rdp = f_rdp.result() if f_rdp else None
    fw = f_fw.result() if f_fw else None
    rdp_problems = []
    if rdp:
        rdp_problems = _check_rdp(rep, G, rdp, fw, tunnels, by_index, cfg)
    pool.shutdown(wait=False)

    data = {
        "time": datetime.datetime.now().isoformat(timespec="seconds"),
        "duration_sec": round(time.time() - t0, 1),
        "version": __version__,
        "host": socket.gethostname(),
        "os": platform.platform(),
        "config": cfg,
        "adapters": all_adapters,
        "tunnels": [t["name"] for t in tunnels],
        "wifi": wifi,
        "external_ip": ext_ip,
        "rdp": rdp,
        "rdp_client_events": rdp_log,
        "net_devices": devices,
        "other_vpn": [a["name"] for a in other_vpn],
        "vpn_via_other": vpn_via_other,
        "vpn_connected": vpn_connected,
        "vpn_bad_ips": vpn_bad_ips,
        "network_links": links,
        "rdp_out": {"ok": rdp_out_ok, "fail": rdp_out_fail},
        "firewall": fw,
        "checks": rep.checks,
    }
    data["verdict"] = verdict(data, physical=physical, gw_ok=gw_ok, inet_ok=inet_ok,
                              dns_fail=dns_fail, vpn_ok=vpn_ok, vpn_fail=vpn_fail,
                              tunnels=tunnels, int_ok=int_ok, int_total=int_total,
                              rdp_problems=rdp_problems, device_problems=device_problems)
    return data


def _auto_internal(tunnels, cfg):
    """Если внутренние адреса не заданы - проверяем DNS-серверы туннеля из сети 10.x."""
    try:
        tnet = ipaddress.IPv4Network(cfg["tunnel_network"], strict=False)
    except ValueError:
        return []
    seen, res = set(), []
    for t in tunnels:
        for d in t.get("dns", []):
            if d not in seen and _in(d, tnet):
                seen.add(d)
                res.append({"name": "DNS туннеля", "host": d})
    return res


def _mb(n):
    return "%.1f МБ" % (n / 1048576.0) if n >= 104857 else "%d КБ" % (n // 1024)


def _check_vpn_devices(rep, G, devices, cfg):
    """Есть ли в системе виртуальные адаптеры VPN-клиентов и исправны ли они.

    Возвращает строки для итога. Пусто, если данных нет (не Windows).
    """
    if devices is None:
        return []
    problems = []
    main_client = next(iter(cfg["patterns"]), None)  # основной клиент - первый в списке
    for client, words in cfg["patterns"].items():
        found = [d for d in devices if any(
            w.lower() in ("%s %s" % (d.get("name") or "", d.get("description") or "")).lower()
            for w in words)]
        if not found:
            rep.add(G, "Адаптер %s" % client, WARN if client == main_client else INFO,
                    "виртуальный адаптер не найден в диспетчере устройств")
            if client != main_client:
                continue  # резервный клиент может быть просто не установлен
            problems.append(
                "Виртуальный адаптер %s не найден в системе: клиент не сможет подключиться. "
                "Драйвер адаптера не установлен или удалён (бывает после обновления Windows "
                "или антивируса) - нужна переустановка клиента %s." % (client, client))
            continue
        for d in found:
            name = d.get("name") or d.get("description") or "?"
            if d.get("problem"):
                text = d["problem_text"]
                if d["problem"] == 22:
                    text += ": включите его в «Сетевых подключениях» (ncpa.cpl)"
                rep.add(G, "Адаптер «%s»" % name, FAIL, text, device=d)
                problems.append("Адаптер %s «%s»: %s." % (client, name, text))
            elif d.get("present") is False:
                rep.add(G, "Адаптер «%s»" % name, FAIL,
                        "записан в системе, но устройство отсутствует", device=d)
                problems.append("Адаптер %s «%s» записан в системе, но устройство "
                                "отсутствует: переустановите клиент %s." % (client, name, client))
            else:
                rep.add(G, "Адаптер «%s»" % name, OK, "установлен и исправен", device=d)
    return problems


def _check_rdp(rep, G, rdp, fw, tunnels, by_index, cfg):
    """Проверки готовности принять RDP. Возвращает список проблем."""
    problems = []

    def bad(name, text, **kw):
        problems.append(text)
        rep.add(G, name, FAIL, text, **kw)

    if rdp["home_edition"]:
        bad("Редакция Windows", "%s (Домашняя): в ней нет сервера RDP, подключиться к ПК "
            "по RDP нельзя" % rdp["edition"])
    if rdp["enabled"] is False:
        bad("Удалённый рабочий стол", "выключен в настройках Windows")
    elif rdp["enabled"]:
        rep.add(G, "Удалённый рабочий стол", OK, "включён, порт %d%s" % (
            rdp["port"], ", NLA" if rdp["nla"] else ""))
    if rdp["service_state"] is not None and rdp["service_state"] != 4:
        bad("Служба TermService", "служба удалённых рабочих столов %s" % rdp["service_text"])
    if not rdp["listening_on"]:
        bad("Порт %d" % rdp["port"], "никто не принимает подключения на порту %d" % rdp["port"])
    else:
        rep.add(G, "Порт %d" % rdp["port"], OK, "принимает подключения на %s"
                % ", ".join(rdp["listening_on"]))

    for t in tunnels:
        ip = t["tunnel_ip"]
        if rdp["listening_on"] and not ({"0.0.0.0", "[::]", ip} & set(rdp["listening_on"])):
            bad("Адрес туннеля", "RDP слушает только %s, а не адрес туннеля %s"
                % (", ".join(rdp["listening_on"]), ip))
        prof = next((p for p in (fw or {}).get("profiles") or []
                     if p.get("index") == t["index"]), None)
        if prof:
            cat = prof["category_text"]
            allowed = winsys.rdp_allowed_for(cat, fw)
            fw_on = winsys.firewall_enabled_for(cat, fw)
            txt = "сеть туннеля «%s»: профиль %s, брандмауэр %s" % (
                t["name"], cat, "включён" if fw_on else ("выключен" if fw_on is False else "?"))
            if fw_on and allowed is False:
                bad("Брандмауэр", txt + ". Входящий RDP для этого профиля запрещён",
                    profile=prof)
            else:
                rep.add(G, "Брандмауэр", OK if allowed or fw_on is False else INFO,
                        txt + (". Входящий RDP разрешён" if allowed else ""), profile=prof)
        if rdp["listening_on"]:
            ok, info = probes.tcp_connect(ip, rdp["port"], timeout=3)
            rep.add(G, "Подключение к себе %s:%d" % (ip, rdp["port"]), OK if ok else WARN,
                    "порт отвечает локально" if ok else info)

        # Ответы администратору должны уходить в туннель
        for src in cfg.get("rdp_sources", []):
            try:
                net = ipaddress.IPv4Network(src, strict=False)
            except ValueError:
                continue
            host = str(next(net.hosts(), net.network_address))
            idx = ad.best_interface(host)
            if idx is not None and idx != t["index"]:
                via = by_index.get(idx)
                bad("Маршрут в %s" % src, "ответы в %s уйдут через «%s», а не через туннель: "
                    "RDP-сессия не установится" % (src, via["name"] if via else idx))
            elif idx is not None:
                rep.add(G, "Маршрут в %s" % src, OK, "через туннель")
    return problems


# --------------------------------------------------------------------------
# Итог
# --------------------------------------------------------------------------
def verdict(data, physical, gw_ok, inet_ok, dns_fail, vpn_ok, vpn_fail, tunnels,
            int_ok, int_total, rdp_problems, device_problems=()):
    """Короткий вывод для человека: что сломано и на каком участке."""
    v = []
    if not physical:
        v.append("Нет подключения к сети: кабель не подключён или Wi-Fi не соединён.")
        return v
    if any(c["status"] == FAIL and "DHCP" in c["summary"] for c in data["checks"]):
        v.append("Сетевой адаптер не получил адрес от роутера (DHCP).")
    if not inet_ok:
        if gw_ok is False:
            v.append("Роутер не отвечает и интернета нет: проблема в локальной сети или Wi-Fi.")
        else:
            v.append("Роутер отвечает, но интернета нет: проблема у провайдера.")
    elif dns_fail:
        v.append("Интернет есть, но часть имён не разрешается: проблемы с DNS.")

    if data.get("vpn_via_other"):
        v.append("Подключение к VPN-серверу идёт через другой VPN (%s): проверка сервера "
                 "не показательна, а обрыв того VPN может оборвать и корпоративный."
                 % ", ".join(data["vpn_via_other"]))

    for name, ips in (data.get("vpn_connected") or {}).items():
        line = "VPN-клиент подключён к %s → %s." % (name, ", ".join(ips))
        bad = set(ips) & set((data.get("vpn_bad_ips") or {}).get(name, []))
        if bad:
            line += " Этот адрес сейчас не проходит проверку: %s." % ", ".join(sorted(bad))
        v.append(line)
    for name, bad in (data.get("vpn_bad_ips") or {}).items():
        if name in vpn_ok:
            v.append("У %s недоступен адрес %s: при переподключении на него клиент "
                     "не подключится." % (name, ", ".join(bad)))

    if vpn_fail and inet_ok:
        if vpn_ok:
            v.append("Недоступны VPN-серверы: %s. Доступны: %s." % (
                ", ".join(vpn_fail), ", ".join(vpn_ok)))
        else:
            v.append("Интернет работает, но ни один VPN-сервер не доступен: "
                     "блокировка в сети пользователя или у провайдера, либо серверы не работают.")

    if not tunnels:
        v.append("Туннель VPN не поднят.")
        v.extend(device_problems)
    else:
        names = ", ".join("%s (%s)" % (t["client"], t["tunnel_ip"]) for t in tunnels)
        route_fail = [c for c in data["checks"]
                      if c["group"] == "Туннель" and "конфликт маршрутов" in c["summary"]]
        no_return = [c for c in data["checks"]
                     if c["group"] == "Туннель" and "ничего не возвращается" in c["summary"]]
        if route_fail:
            v.append("Туннель %s поднят, но трафик к внутренней сети уходит мимо него: "
                     "конфликт адресов с локальной сетью пользователя." % names)
        elif int_total and not int_ok:
            if no_return:
                v.append("Туннель %s поднят, адрес получен, но сервер не возвращает трафик. "
                         "Вероятна зависшая сессия: переподключите VPN." % names)
            else:
                v.append("Туннель %s поднят, но внутренние адреса не отвечают." % names)
        elif int_total:
            v.append("Туннель %s работает: внутренние адреса отвечают (%d из %d)."
                     % (names, int_ok, int_total))
        else:
            v.append("Туннель %s поднят. Для проверки трафика добавьте внутренние адреса "
                     "в раздел [internal]." % names)
        if rdp_problems:
            v.append("Входящий RDP к этому ПК не заработает: " + "; ".join(rdp_problems) + ".")
    out = data.get("rdp_out") or {}
    if out.get("fail"):
        hint = " Туннель при этом работает: вероятно, сервер выключен или порт закрыт " \
               "на его стороне." if tunnels and int_ok else ""
        v.append("RDP-серверы недоступны: %s.%s" % (", ".join(out["fail"]), hint))
    elif out.get("ok"):
        v.append("RDP-серверы доступны: %s." % ", ".join(out["ok"]))
    problems = (not tunnels) or out.get("fail") or (int_total and not int_ok) or vpn_fail
    if data.get("other_vpn") and problems:
        v.append("Также включён другой VPN (%s). Если проблема не объясняется выше, "
                 "проверьте с выключенным." % ", ".join(data["other_vpn"]))
    if not v:
        v.append("Проблем не найдено.")
    return v
