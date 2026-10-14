# -*- coding: utf-8 -*-
"""Раздел «Информация»: состояние VPN, RDP и адресов в реальном времени.

Info.read() вызывается раз в пару секунд из фонового потока и возвращает
строки [(название, значение, статус)]. Дорогие запросы (внешний IP,
журнал клиента RDP) обновляются реже и кешируются.
"""

import datetime
import time

from . import adapters as ad, continent, diagnose, probes, winsys

RDP_PROCS = {"mstsc", "msrdc", "msrdcw", "rdcman", "mremoteng", "remotedesktopmanager",
             "royalts"}
EXT_EVERY = 60     # внешний IP - раз в минуту и при смене VPN
RDP_LOG_EVERY = 15  # журнал клиента RDP (UDP или TCP)

OK, WARN, FAIL, INFO = "ok", "warn", "fail", "info"


def _hms(iso):
    return (iso or "")[11:19]


def _dur(sec):
    sec = int(sec)
    if sec >= 3600:
        return "%d ч %02d мин" % (sec // 3600, sec % 3600 // 60)
    if sec >= 60:
        return "%d мин" % (sec // 60)
    return "%d с" % sec


def rdp_transport(events, udp_socket=None):
    """По какому протоколу идёт текущий сеанс RDP: (текст, статус).

    По журналу клиента: после последнего подключения (1024) событие 1103 -
    UDP-канал поднят, 1105 - разорван. Без журнала - по UDP-сокету клиента."""
    evs = events or []
    start = max((i for i, e in enumerate(evs) if e.get("id") == 1024), default=None)
    if start is not None:
        last = None
        tried = False
        for e in evs[start:]:
            if e.get("id") in (1103, 1105):
                last = e
            tried = tried or e.get("id") == 1102
        if last and last["id"] == 1103:
            return "UDP (с %s), управление по TCP" % _hms(last.get("time")), OK
        if last and last["id"] == 1105:
            return "TCP: UDP-канал разорван в %s" % _hms(last.get("time")), WARN
        if tried:
            return "TCP: UDP-канал не установился", WARN
        return "TCP", INFO
    if udp_socket:
        return "вероятно, UDP (у клиента открыт UDP-сокет)", OK
    if udp_socket is False:
        return "TCP", INFO
    return "неизвестно", INFO


class Info:
    def __init__(self, cfg):
        self.cfg = cfg
        self.patterns = [w for ws in cfg["patterns"].values() for w in ws]
        self.ext = None          # (ip, время) или None
        self.ext_key = None      # набор туннелей/VPN, при котором получен внешний IP
        self.ext_busy = False
        self.rdp_events = None
        self.rdp_events_at = 0
        self.rdp_since = {}      # соединение RDP -> когда впервые увидели
        self.vpn_list = None     # серверы VPN из настроек и из настроек Континента
        self.vpn_ips = set()     # их адреса по DNS

    # ---- дорогие запросы -------------------------------------------------
    def want_external(self, key, now):
        return not self.ext_busy and (self.ext is None or key != self.ext_key
                                      or now - self.ext[1] >= EXT_EVERY)

    def refresh_external(self, key):
        self.ext_busy = True
        try:
            if self.vpn_list is None:
                try:
                    self.vpn_list = list(self.cfg.get("vpn", [])) + diagnose._continent_servers(
                        continent.info(), self.cfg.get("vpn", []))
                except Exception:
                    self.vpn_list = list(self.cfg.get("vpn", []))
            ips = set()
            for v in self.vpn_list:
                ips.update(probes.resolve_all(v["host"])[0])
            self.vpn_ips = ips
            ip, err = probes.external_ip()
            self.ext = (ip or "нет связи", time.time())
            self.ext_key = key
        finally:
            self.ext_busy = False

    def _rdp_log(self, now):
        if now - self.rdp_events_at >= RDP_LOG_EVERY:
            self.rdp_events_at = now
            self.rdp_events = winsys.rdp_client_events(12 * 60)
        return self.rdp_events

    # ---- снимок ----------------------------------------------------------
    def read(self, adapters=None, conns=None, udp=None, now=None):
        """Строки раздела: [(название, значение, статус)] и ключ состояния VPN."""
        now = now or time.time()
        adapters = ad.get_adapters() if adapters is None else adapters
        conns = ad.tcp_connections() if conns is None else conns
        tunnels, local, idle_vpn, _c = diagnose.classify(adapters, self.cfg)
        other = diagnose._other_vpn(adapters, self.cfg)
        rows = []

        # VPN
        client_tcp = winsys.client_links({"tcp": conns or []}, self.patterns)["client"]
        server = ""
        if client_tcp:
            c = client_tcp[0]
            if c["remote"].startswith("127."):
                far = [x for x in conns or [] if x.get("remote") in self.vpn_ips
                       and winsys._proc_matches(x, winsys.PROXY_PROCS)]
                if far:
                    server = ", сервер %s:%s через прокси %s" % (
                        far[0]["remote"], far[0]["rport"], far[0].get("process") or "?")
                else:
                    server = ", через локальный прокси %s:%s" % (c["remote"], c["rport"])
            else:
                server = ", сервер %s:%s" % (c["remote"], c["rport"])
        if tunnels:
            names = sorted({t["client"] for t in tunnels})
            rows.append(("VPN", "подключён: %s%s" % (", ".join(names), server), OK))
        elif idle_vpn:
            rows.append(("VPN", "не подключён (%s установлен, туннель не поднят)"
                         % ", ".join(sorted({a["client"] for a in idle_vpn})), FAIL))
        else:
            rows.append(("VPN", "не подключён", FAIL))
        if other:
            rows.append(("Другой VPN", "включён: %s" % ", ".join(a["name"] for a in other),
                         WARN))

        # адреса
        for t in tunnels:
            rows.append(("Внутренний IP", "%s  (%s)" % (t["tunnel_ip"], t["name"]), OK))
        if not tunnels:
            rows.append(("Внутренний IP", "нет: туннель VPN не поднят", FAIL))
        lan = [a for a in local if a.get("gateway") and ad.ipv4_addrs(a)
               and not diagnose._is_virtual(a)]
        for a in lan[:2]:
            rows.append(("Локальный IP", "%s  (%s, шлюз %s)" % (
                ad.ipv4_addrs(a)[0], a["name"], a["gateway"][0]), INFO))
        if not lan:
            rows.append(("Локальный IP", "нет подключения к сети", FAIL))
        key = (tuple(sorted(t["name"] for t in tunnels)),
               tuple(sorted(a["name"] for a in other)))
        if self.ext:
            age = now - self.ext[1]
            rows.append(("Внешний IP", "%s  (проверен %s назад)" % (self.ext[0], _dur(age)),
                         FAIL if self.ext[0] == "нет связи" else OK))
        else:
            rows.append(("Внешний IP", "определяется…", INFO))

        # RDP
        rdp = [c for c in conns or [] if (c.get("process") or "").lower() in RDP_PROCS
               or c.get("rport") == 3389]
        incoming = [c for c in conns or [] if c.get("lport") == 3389]
        seen = set()
        for c in rdp:
            k = (c["remote"], c["rport"], c["lport"])
            seen.add(k)
            self.rdp_since.setdefault(k, now)
        self.rdp_since = {k: v for k, v in self.rdp_since.items() if k in seen}
        if rdp:
            c = rdp[0]
            k = (c["remote"], c["rport"], c["lport"])
            rows.append(("RDP", "подключён к %s:%s (%s, %s)" % (
                c["remote"], c["rport"], c.get("process") or "?",
                _dur(now - self.rdp_since[k])), OK))
            pids = udp if udp is not None else ad.udp_pids()
            udp_sock = None if pids is None else c.get("pid") in pids
            text, st = rdp_transport(self._rdp_log(now), udp_sock)
            rows.append(("Протокол RDP", text, st))
        else:
            rows.append(("RDP", "нет подключения", INFO))
        if incoming:
            rows.append(("Входящий RDP", "к этому ПК подключён %s" % ", ".join(
                sorted({c["remote"] for c in incoming})), INFO))
        rows.append(("Обновлено", datetime.datetime.fromtimestamp(now).strftime("%H:%M:%S"),
                     INFO))
        return rows, key
