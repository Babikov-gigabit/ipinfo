# -*- coding: utf-8 -*-
"""Фоновый мониторинг: ловим обрывы и записываем, что в этот момент пропало.

Каждые несколько секунд параллельно пингуются роутер, интернет, внутренние
адреса туннеля и RDP-серверы, проверяется, на месте ли адаптер VPN и его
адрес, Wi-Fi и другой VPN. Раз в полминуты имя VPN-сервера заново
разрешается через DNS и смотрится, к какому из его адресов подключён клиент.
В журнал пишутся только изменения состояния.
Отдельно читается журнал клиента RDP: на каждое отключение RDP выводится
разбор - что было со связью в последние секунды перед ним.
"""

import collections
import concurrent.futures
import datetime
import json
import os
import threading
import time

from . import adapters as ad, continent, diagnose, probes, winsys
from .report import logs_dir, log

HISTORY_SEC = 120     # сколько секунд истории держать для разбора обрыва RDP
FAILS_TO_DOWN = 2     # столько неудач подряд - считаем узел недоступным
WIFI_EVERY = 10       # секунд между опросами Wi-Fi (netsh)
RDP_LOG_EVERY = 20    # секунд между чтениями журнала клиента RDP
RDP_TCP_EVERY = 30    # секунд между проверками порта RDP-серверов
VPN_EVERY = 30        # секунд между проверками DNS VPN-сервера и адреса подключения
INCIDENTS_SEC = 1800  # за сколько секунд до обрыва RDP перечислять проблемы, если начало сеанса неизвестно
# программы-клиенты RDP: их TCP-соединения отслеживаются каждый цикл
RDP_PROCS = {"mstsc", "msrdc", "msrdcw", "rdcman", "mremoteng", "remotedesktopmanager",
             "royalts"}


def _hms(epoch):
    return datetime.datetime.fromtimestamp(epoch).strftime("%H:%M:%S") if epoch else "?"


def _minutes(sec):
    sec = int(sec)
    return "%d мин %d с" % (sec // 60, sec % 60) if sec >= 60 else "%d с" % sec


def _event_epoch(iso):
    """Время события Windows ('2026-10-13T18:22:54.1234567+03:00') в секундах epoch."""
    if not iso:
        return None
    import re
    iso = re.sub(r"(\.\d{6})\d+", r"\1", iso)
    try:
        return datetime.datetime.fromisoformat(iso).timestamp()
    except (ValueError, OSError, OverflowError):
        return None


class Probe:
    """Один проверяемый узел: ping по IP, состояние up/down с порогом."""

    def __init__(self, kind, name, ip):
        self.kind, self.name, self.ip = kind, name, ip
        self.up = None
        self.fails = 0
        self.down_since = None
        self.lost = 0
        self.sent = 0
        self.downtime = 0.0
        self.drops = 0


class Monitor:
    def __init__(self, cfg, interval=2.0, on_event=None):
        self.cfg = cfg
        self.interval = max(1.0, float(interval))
        self.on_event = on_event
        self.stop_event = threading.Event()
        self.thread = None
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=16)
        self.history = collections.deque()
        self.events = []
        self.started = None
        self.probes = []
        self.rdp_targets = []
        self.state = {}
        self.vpn = {}          # имя сервера -> {"ips": [...], "used": [...]}
        self._vpn_fut = None
        self.vpn_list = list(cfg.get("vpn", []))  # + серверы из настроек Континента
        self.vpn_conns = None  # соединения и попытки подключения VPN-клиента
        self.rdp_conns = None  # открытые TCP-соединения клиента RDP: ключ -> dict
        self.rdp_closed = []   # недавно закрытые соединения клиента RDP
        self.rdp_session = None  # {"server", "t"} - последнее подключение по журналу
        self.rdp_udp_lost = None  # время последнего разрыва UDP-канала RDP
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        self.text_path = os.path.join(logs_dir(), "monitor-%s.log" % stamp)
        self.json_path = os.path.join(logs_dir(), "monitor-%s.jsonl" % stamp)

    # ---- запись -----------------------------------------------------------
    def emit(self, level, text, **data):
        now = datetime.datetime.now()
        ev = {"time": now.isoformat(timespec="seconds"), "level": level, "text": text}
        ev.update(data)
        self.events.append(ev)
        line = "%s %s %s" % (now.strftime("%H:%M:%S"), {"ok": "  ", "warn": "!!", "fail": "XX",
                                                        "info": "--"}.get(level, "  "), text)
        try:
            with open(self.text_path, "a", encoding="utf-8") as f:
                f.write(now.strftime("%Y-%m-%d ") + line + "\n")
            with open(self.json_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(ev, ensure_ascii=False, default=str) + "\n")
        except OSError as e:
            log.warning("не удалось записать журнал мониторинга: %s", e)
        if self.on_event:
            try:
                self.on_event(ev, line)
            except Exception:
                pass

    # ---- подготовка -------------------------------------------------------
    def _snapshot(self):
        """Адаптеры, туннель, другой VPN - дёшево, через WinAPI."""
        adapters = ad.get_adapters(include_down=True)
        tunnels, local, _idle, _c = diagnose.classify(adapters, self.cfg)
        other = diagnose._other_vpn(adapters, self.cfg)
        physical = [a for a in local if a["ipv4"] and a["gateway"]
                    and not diagnose._is_virtual(a)]
        return {
            "tunnels": {t["name"]: t["tunnel_ip"] for t in tunnels},
            "tunnel_index": {t["name"]: t["index"] for t in tunnels},
            "tunnel_dns": [d for t in tunnels for d in t["dns"]],
            "physical": {a["name"]: (ad.ipv4_addrs(a)[0], a["gateway"][0]) for a in physical},
            "other_vpn": sorted(a["name"] for a in other),
        }

    def _setup_probes(self, snap):
        probes_ = []
        for name, (_ip, gw) in snap["physical"].items():
            if ":" not in gw:
                probes_.append(Probe("gateway", "роутер %s" % gw, gw))
        for host in self.cfg["internet"][:2]:
            ip, _ = probes.resolve4(host)
            if ip:
                probes_.append(Probe("internet", "интернет %s" % host, ip))
        internal = self.cfg["internal"] or diagnose._auto_internal(
            [{"dns": snap["tunnel_dns"]}], self.cfg)
        for i in internal[:3]:
            ip, _ = probes.resolve4(i["host"])
            if ip:
                probes_.append(Probe("internal", "туннель %s" % i["host"], ip))
        for t in self.cfg.get("rdp_targets", []):
            ip, _ = probes.resolve4(t["host"])
            if ip:
                probes_.append(Probe("rdp", "RDP-сервер %s" % t["host"], ip))
                self.rdp_targets.append(dict(t, ip=ip, ok=None))
        return probes_

    # ---- цикл -------------------------------------------------------------
    def start(self):
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()

    def _run(self):
        try:
            self._loop()
        except Exception as e:
            log.exception("мониторинг остановлен из-за ошибки")
            self.emit("fail", "мониторинг остановлен из-за ошибки: %s" % e)
        finally:
            self.pool.shutdown(wait=False)

    def _loop(self):
        self.started = time.time()
        snap = self._snapshot()
        self.state = snap
        self.probes = self._setup_probes(snap)
        self.emit("info", "мониторинг запущен: каждые %g с проверяются %s" % (
            self.interval, ", ".join(p.name for p in self.probes) or "только адаптеры"))
        if snap["tunnels"]:
            self.emit("info", "туннель: %s" % ", ".join(
                "«%s» %s" % kv for kv in snap["tunnels"].items()))
        else:
            self.emit("warn", "туннель не поднят")
        if snap["other_vpn"]:
            self.emit("info", "другой VPN включён: %s" % ", ".join(snap["other_vpn"]))
        if not self.cfg.get("rdp_targets"):
            self.emit("info", "RDP-серверы не заданы в [rdp] targets: проверяю без них")

        wifi = winsys.wifi_info()
        if wifi:
            self.emit("info", "Wi-Fi «%s», точка %s, сигнал %s%%" % (
                wifi.get("ssid"), wifi.get("bssid"), wifi.get("signal_pct")))
        stats = self._tunnel_stats(snap)
        try:
            self.vpn_list += diagnose._continent_servers(continent.info(), self.vpn_list)
        except Exception as e:
            log.warning("настройки Континента: %s", e)
        if self.vpn_list:
            self._apply_vpn(self._read_vpn())
        self._check_tcp(time.time())
        last_wifi = last_rdp_log = last_rdp_tcp = last_vpn = time.time()
        rdp_seen = set(self._rdp_event_key(e) for e in (winsys.rdp_client_events(10) or []))
        last_tick = time.time()

        while not self.stop_event.wait(self.interval):
            now = time.time()
            gap = now - last_tick
            last_tick = now
            if gap > max(30, self.interval * 10):
                self.emit("warn", "пауза %d с: компьютер спал или завис" % gap, gap_sec=round(gap))

            # пинги параллельно
            futs = {p: self.pool.submit(probes.echo, p.ip, 32, 1000) for p in self.probes}
            tick = {"t": now, "probes": {}}
            for p, f in futs.items():
                st, rtt = f.result()
                self._update_probe(p, st == probes.IP_SUCCESS, rtt, now)
                tick["probes"][p.name] = p.up

            # адаптеры
            new = self._snapshot()
            self._diff_snapshot(self.state, new)
            self.state = new
            tick["tunnel"] = bool(new["tunnels"])
            tick["other_vpn"] = new["other_vpn"]

            # счётчики туннеля
            new_stats = self._tunnel_stats(new)
            for name, s in new_stats.items():
                old = stats.get(name)
                if old and s:
                    tick["tunnel_rx"] = s["rx_bytes"] - old["rx_bytes"]
                    tick["tunnel_tx"] = s["tx_bytes"] - old["tx_bytes"]
                    if s["rx_errors"] > old["rx_errors"] or s["rx_discards"] > old["rx_discards"]:
                        self.emit("warn", "ошибки приёма на «%s»: +%d, отброшено +%d" % (
                            name, s["rx_errors"] - old["rx_errors"],
                            s["rx_discards"] - old["rx_discards"]))
            stats = new_stats

            if now - last_wifi >= WIFI_EVERY:
                last_wifi = now
                w = winsys.wifi_info()
                self._diff_wifi(wifi, w)
                wifi = w
            tick["wifi"] = (wifi or {}).get("bssid")

            if self.rdp_targets and now - last_rdp_tcp >= RDP_TCP_EVERY:
                last_rdp_tcp = now
                self._check_rdp_ports()

            if self._vpn_fut and self._vpn_fut.done():
                try:
                    self._apply_vpn(self._vpn_fut.result())
                except Exception as e:
                    log.warning("проверка VPN-сервера: %s", e)
                self._vpn_fut = None
            if self.vpn_list and not self._vpn_fut and now - last_vpn >= VPN_EVERY:
                last_vpn = now
                self._vpn_fut = self.pool.submit(self._read_vpn)
            tick["vpn"] = {n: list(v.get("used") or []) for n, v in self.vpn.items()}

            tick["rdp_tcp"] = self._check_tcp(now)

            self.history.append(tick)
            while self.history and now - self.history[0]["t"] > HISTORY_SEC:
                self.history.popleft()

            if now - last_rdp_log >= RDP_LOG_EVERY:
                last_rdp_log = now
                self._check_rdp_log(rdp_seen)

        self._check_rdp_log(rdp_seen)
        self.emit("info", self.summary())

    # ---- состояние узлов -------------------------------------------------
    def _update_probe(self, p, ok, rtt, now):
        p.sent += 1
        if ok:
            if p.up is False:
                dur = now - (p.down_since or now)
                p.downtime += dur
                self.emit("ok", "%s снова отвечает (не было %d с)" % (p.name, dur),
                          probe=p.name, kind=p.kind, down_sec=round(dur))
            elif p.up is None:
                pass
            p.up, p.fails, p.down_since = True, 0, None
            return
        p.lost += 1
        p.fails += 1
        if p.up is not False and p.fails >= FAILS_TO_DOWN:
            p.up = False
            p.drops += 1
            p.down_since = now - self.interval * (FAILS_TO_DOWN - 1)
            self.emit("fail", "%s не отвечает" % p.name, probe=p.name, kind=p.kind,
                      context=self._context())

    def _context(self):
        """Что в этот момент со всем остальным - для разбора причины."""
        return {
            "tunnel": dict(self.state.get("tunnels", {})),
            "other_vpn": self.state.get("other_vpn"),
            "probes": {p.name: p.up for p in self.probes},
        }

    def _diff_snapshot(self, old, new):
        for name, ip in old["tunnels"].items():
            if name not in new["tunnels"]:
                self.emit("fail", "туннель «%s» пропал (адрес %s потерян)" % (name, ip),
                          tunnel=name)
            elif new["tunnels"][name] != ip:
                self.emit("warn", "туннель «%s» сменил адрес: %s → %s" % (
                    name, ip, new["tunnels"][name]), tunnel=name)
        for name, ip in new["tunnels"].items():
            if name not in old["tunnels"]:
                self.emit("ok", "туннель «%s» поднят, адрес %s" % (name, ip), tunnel=name)
        for name, (ip, gw) in old["physical"].items():
            if name not in new["physical"]:
                self.emit("fail", "подключение «%s» пропало" % name, adapter=name)
            elif new["physical"][name] != (ip, gw):
                self.emit("warn", "«%s»: адрес/шлюз сменились %s/%s → %s/%s" % (
                    (name, ip, gw) + new["physical"][name]), adapter=name)
        for name in new["physical"]:
            if name not in old["physical"]:
                self.emit("ok", "подключение «%s» появилось: %s, шлюз %s" % (
                    (name,) + new["physical"][name]), adapter=name)
        if old["other_vpn"] != new["other_vpn"]:
            self.emit("warn", "другой VPN: %s → %s" % (
                ", ".join(old["other_vpn"]) or "выключен",
                ", ".join(new["other_vpn"]) or "выключен"))

    def _diff_wifi(self, old, new):
        if old and not new:
            self.emit("fail", "Wi-Fi отключился")
        elif new and not old:
            self.emit("ok", "Wi-Fi подключён: «%s»" % new.get("ssid"))
        elif old and new:
            if old.get("bssid") != new.get("bssid"):
                self.emit("warn", "Wi-Fi переключился на другую точку: %s → %s (сигнал %s%%)" % (
                    old.get("bssid"), new.get("bssid"), new.get("signal_pct")))
            sig = new.get("signal_pct")
            if sig is not None and sig < 40 and (old.get("signal_pct") or 100) >= 40:
                self.emit("warn", "слабый сигнал Wi-Fi: %d%%" % sig)

    def _tunnel_stats(self, snap):
        return {name: ad.if_stats(idx) for name, idx in snap.get("tunnel_index", {}).items()}

    def _check_rdp_ports(self):
        for t in self.rdp_targets:
            ok, info = probes.tcp_connect(t["ip"], t["port"], timeout=5)
            if ok != t["ok"]:
                if ok:
                    self.emit("ok", "порт RDP %s:%d открыт (%d мс)" % (t["host"], t["port"], info))
                else:
                    self.emit("fail", "порт RDP %s:%d: %s" % (t["host"], t["port"], info))
            t["ok"] = ok

    # ---- VPN-сервер: DNS и адрес подключения ------------------------------
    def _read_vpn(self):
        """Адреса имён VPN-серверов из DNS и к каким из них есть подключение."""
        links = winsys.network_links()
        res = {}
        for s in self.vpn_list:
            ips, info = probes.resolve_all(s["host"])
            if not ips:
                res[s["name"]] = {"host": s["host"], "ips": [], "error": info, "used": None}
                continue
            used = None
            if links is not None:
                line = diagnose.vpn_connection(links, ips, s, self.cfg)
                used = line[2] if line else []
            res[s["name"]] = {"host": s["host"], "ips": ips, "used": used}
        return res

    def _apply_vpn(self, res):
        """Пишет в журнал первые значения и все изменения DNS и адреса подключения."""
        for name, r in res.items():
            old = self.vpn.get(name)
            first = old is None
            old = old or {}
            if r.get("error"):
                if first or old.get("ips"):
                    self.emit("warn", "%s: DNS - %s: %s" % (name, r["host"], r["error"]),
                              vpn=name, dns_error=r["error"])
            elif first:
                self.emit("info", "%s: DNS %s → %s" % (name, r["host"], ", ".join(r["ips"])),
                          vpn=name, ips=r["ips"])
            elif set(r["ips"]) != set(old.get("ips") or []):
                self.emit("warn", "%s: DNS %s изменился: %s → %s" % (
                    name, r["host"], ", ".join(old.get("ips") or []) or "нет ответа",
                    ", ".join(r["ips"])), vpn=name, ips=r["ips"], old_ips=old.get("ips"))
            used, old_used = r.get("used"), old.get("used")
            if used is None:          # соединения не прочитать (не Windows / ошибка)
                r["used"] = old_used
            elif first:
                if used:
                    self.emit("info", "%s: клиент подключён к %s" % (name, ", ".join(used)),
                              vpn=name, used=used)
                else:
                    self.emit("info", "%s: соединений с адресами сервера нет" % name, vpn=name)
            elif set(used) != set(old_used or []):
                if used and old_used:
                    self.emit("warn", "%s: клиент переключился с %s на %s" % (
                        name, ", ".join(old_used), ", ".join(used)),
                        vpn=name, used=used, old_used=old_used)
                elif used:
                    self.emit("ok", "%s: клиент подключён к %s" % (name, ", ".join(used)),
                              vpn=name, used=used)
                else:
                    self.emit("warn", "%s: соединение с сервером %s пропало" % (
                        name, ", ".join(old_used)), vpn=name, old_used=old_used)
            if r.get("error") and old.get("ips"):
                r["ips"] = old["ips"]  # помним последний ответ, чтобы увидеть смену
            self.vpn[name] = r

    # ---- журнал клиента RDP -----------------------------------------------
    @staticmethod
    def _rdp_event_key(e):
        return (e.get("time"), e.get("id"))

    def _check_rdp_log(self, seen):
        events = winsys.rdp_client_events(5)
        for e in events or []:
            key = self._rdp_event_key(e)
            if key in seen:
                continue
            seen.add(key)
            at = _event_epoch(e.get("time"))
            if e["id"] == 1024:
                self.rdp_session = {"server": e.get("server", "?"), "t": at}
                self.emit("info", "RDP %s: подключение к %s" % (_hms(at), e.get("server", "?")),
                          rdp=e)
            elif e["id"] == 1026:
                cause = self.describe_disconnect(e)
                self.emit("fail" if e.get("reason") not in (1, 2) else "info",
                          "RDP %s: сеанс отключён - %s (код %s).\n%s" % (
                              _hms(at), e.get("reason_text"), e.get("reason"), cause),
                          rdp=e, cause=cause)
            elif e["id"] == 1105:
                self.rdp_udp_lost = at
                self.emit("warn", "RDP %s: UDP-канал разорван, сеанс перешёл на TCP" % _hms(at),
                          rdp=e)

    # ---- TCP-соединения клиента RDP ------------------------------------------
    def _is_rdp_conn(self, c):
        if (c.get("process") or "").lower() in RDP_PROCS or c.get("rport") == 3389:
            return True
        return any(c.get("remote") == t.get("ip") and c.get("rport") == t.get("port")
                   for t in self.rdp_targets)

    def _check_tcp(self, now):
        """Один снимок TCP-таблицы на цикл: соединения клиента RDP и VPN-клиента."""
        conns = ad.tcp_connections(syn_sent=True)
        if conns is None:
            return None
        self._check_vpn_tcp(conns, now)
        return self._check_rdp_tcp(now, conns)

    def _check_vpn_tcp(self, conns, now):
        """Попытки подключения и соединения самого VPN-клиента: видно, какой адрес
        сервера он пробовал первым, какой не ответил и к какому подключился."""
        patterns = [w for ws in self.cfg["patterns"].values() for w in ws]
        ports = {v["port"] for v in self.vpn_list if v.get("proto") == "tcp"}
        cur = {}
        for c in winsys.client_links({"tcp": conns}, patterns)["client"]:
            if not ports or c["rport"] in ports:
                cur[(c["remote"], c["rport"], c["lport"])] = c
        first = self.vpn_conns is None
        old = self.vpn_conns or {}
        for k, c in cur.items():
            prev = old.get(k)
            c["since"] = prev.get("since") if prev else (None if first else now)
            who = "VPN-клиент (%s)" % (c.get("process") or "pid %s" % c.get("pid"))
            ep = "%s:%d" % (c["remote"], c["rport"])
            if c["state"] == "syn_sent" and not prev:
                self.emit("info", "%s пробует подключиться к %s" % (who, ep), vpn_tcp=c)
            elif c["state"] == "established" and (not prev or prev["state"] != "established"):
                if first:
                    self.emit("info", "%s уже подключён к %s" % (who, ep), vpn_tcp=c)
                else:
                    waited = (" (ответ через %s)" % _minutes(now - prev["since"])
                              if prev and prev.get("since") else "")
                    c["since"] = now
                    self.emit("ok", "%s подключился к %s%s" % (who, ep, waited), vpn_tcp=c)
        for k, c in old.items():
            if k in cur:
                continue
            who = "VPN-клиент (%s)" % (c.get("process") or "pid %s" % c.get("pid"))
            ep = "%s:%d" % (c["remote"], c["rport"])
            if c["state"] == "syn_sent":
                self.emit("warn", "%s: %s не ответил, попытка прекращена" % (who, ep),
                          vpn_tcp=c)
            else:
                lived = (" (было открыто %s)" % _minutes(now - c["since"])
                         if c.get("since") else "")
                self.emit("warn", "%s: соединение с %s закрыто%s" % (who, ep, lived),
                          vpn_tcp=c)
        self.vpn_conns = cur

    def _check_rdp_tcp(self, now, conns=None):
        """Сравнивает открытые TCP-соединения клиента RDP с прошлым циклом.

        Возвращает число открытых соединений (None, если прочитать не удалось)."""
        if conns is None:
            conns = ad.tcp_connections()
        if conns is None:
            return None
        cur = {}
        for c in conns:
            if c.get("state", "established") == "established" and self._is_rdp_conn(c):
                cur[(c["remote"], c["rport"], c["lport"])] = c
        first = self.rdp_conns is None
        old = self.rdp_conns or {}
        for k, c in cur.items():
            if k in old:
                c["since"] = old[k].get("since")
                continue
            c["since"] = None if first else now
            self.emit("info", "RDP: TCP-соединение %s → %s:%d %s" % (
                c.get("process") or "pid %s" % c.get("pid"), c["remote"], c["rport"],
                "уже открыто" if first else "открыто"), rdp_tcp=c)
        for k, c in old.items():
            if k in cur:
                continue
            closed = dict(c, closed=now)
            self.rdp_closed = (self.rdp_closed + [closed])[-20:]
            lived = (" (было открыто %s)" % _minutes(now - c["since"])) if c.get("since") else ""
            self.emit("warn", "RDP: TCP-соединение %s → %s:%d закрыто%s" % (
                c.get("process") or "pid %s" % c.get("pid"), c["remote"], c["rport"], lived),
                rdp_tcp=closed)
        self.rdp_conns = cur
        return len(cur)

    def _route_of(self, ip):
        """Через какой адаптер идёт трафик к ip."""
        idx = ad.best_interface(ip)
        if idx is None:
            return None
        for a in ad.get_adapters(include_down=True):
            if a.get("index") == idx:
                return a["name"]
        return None

    def describe_disconnect(self, e):
        """Подробный разбор отключения RDP: сеанс, UDP, TCP, маршрут, проблемы сети."""
        at = _event_epoch(e.get("time")) or time.time()
        out = []
        sess = self.rdp_session if self.rdp_session and (self.rdp_session.get("t") or 0) <= at \
            else None
        if sess and sess.get("t"):
            out.append("Сеанс к %s с %s, длился %s." % (sess["server"], _hms(sess["t"]),
                                                       _minutes(at - sess["t"])))
        start = (sess or {}).get("t") or max(self.started or at, at - INCIDENTS_SEC)
        if self.rdp_udp_lost and start <= self.rdp_udp_lost <= at + 5:
            out.append("UDP-канал RDP разорвался в %s, за %s до отключения." % (
                _hms(self.rdp_udp_lost), _minutes(max(0, at - self.rdp_udp_lost))))
        closed = [c for c in self.rdp_closed if at - 600 <= c["closed"] <= at + 60]
        for c in closed[-2:]:
            out.append("TCP-соединение %s → %s:%d закрылось в %s." % (
                c.get("process") or "RDP", c["remote"], c["rport"], _hms(c["closed"])))
        ip = (closed[-1]["remote"] if closed else
              next((t["ip"] for t in self.rdp_targets
                    if sess and t["host"] in (sess.get("server") or "")), None))
        if ip:
            via = self._route_of(ip)
            if via:
                out.append("Трафик к %s идёт через «%s»." % (ip, via))
        incidents = [ev for ev in self.events
                     if ev["level"] in ("warn", "fail") and not ev.get("rdp")
                     and not ev.get("rdp_tcp")
                     and start - 5 <= (_event_epoch(ev["time"]) or 0) <= at + 5]
        if incidents:
            out.append("Проблемы сети за время сеанса: " + "; ".join(
                "%s %s" % (ev["time"][11:19], ev["text"]) for ev in incidents[-6:]) + ".")
        window = self.explain_disconnect(at)
        if e.get("reason") == 2308 and not incidents and window.startswith("Сеть, интернет"):
            out.append("Сеть и туннель за это время не пропадали. Код 2308 значит, что "
                       "TCP-соединение RDP было закрыто. Если обрыв обнаружился, когда вы "
                       "вернулись к окну после простоя, соединение, скорее всего, закрыл по "
                       "неактивности кто-то на пути: VPN-клиент, другой VPN или NAT роутера. "
                       "Клиент RDP узнаёт об этом только при первой попытке отправить данные.")
        else:
            out.append(window)
        return "\n".join("    " + line for line in out)

    def explain_disconnect(self, at=None, window=30):
        """Что пропадало за window секунд до момента at (время события RDP)."""
        at = at or time.time()
        ticks = [t for t in self.history if at - window <= t["t"] <= at + self.interval]
        if not ticks:
            return "Данных о сети за это время нет."
        down = collections.OrderedDict()
        for t in ticks:
            for name, up in t["probes"].items():
                if up is False:
                    down[name] = True
        kinds = {p.name: p.kind for p in self.probes}
        down_kinds = {kinds.get(n) for n in down}
        if not all(t["tunnel"] for t in ticks):
            return "В это время пропадал туннель VPN."
        vpn_states = {json.dumps(t.get("vpn") or {}, sort_keys=True) for t in ticks}
        if len(vpn_states) > 1:
            return "В это время VPN-клиент переподключался к серверу (сменился адрес " \
                   "подключения)."
        if "gateway" in down_kinds:
            return "В это время не отвечал роутер: проблема в локальной сети или Wi-Fi."
        if len({t.get("wifi") for t in ticks if t.get("wifi")}) > 1:
            return "В это время Wi-Fi переключался между точками доступа."
        if "internet" in down_kinds:
            return "В это время пропадал интернет при работающем роутере: проблема у провайдера."
        if len({tuple(t.get("other_vpn") or ()) for t in ticks}) > 1:
            return "В это время включался или выключался другой VPN."
        if "internal" in down_kinds:
            return "Туннель был поднят, но внутренние адреса не отвечали: трафик через " \
                   "туннель не шёл."
        if "rdp" in down_kinds:
            return "Сеть и туннель работали, не отвечал сам RDP-сервер."
        return "Сеть, интернет и туннель в это время работали: обрыв на стороне RDP " \
               "(сервер, сессия или UDP-транспорт RDP)."

    # ---- итог -------------------------------------------------------------
    def summary(self):
        dur = time.time() - (self.started or time.time())
        parts = ["мониторинг %d мин" % (dur // 60)]
        for p in self.probes:
            loss = 100.0 * p.lost / p.sent if p.sent else 0
            s = "%s: потери %.1f%%" % (p.name, loss)
            if p.drops:
                s += ", обрывов %d, без связи %d с" % (p.drops, p.downtime)
            parts.append(s)
        rdp = [e for e in self.events if e.get("rdp", {}).get("id") == 1026]
        if rdp:
            parts.append("отключений RDP: %d" % len(rdp))
        return "; ".join(parts)
