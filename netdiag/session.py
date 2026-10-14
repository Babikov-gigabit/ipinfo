# -*- coding: utf-8 -*-
"""Блокировка, простой и сон ПК, к которому подключаются по RDP.

Запускается на удалённом ПК: какие таймеры там настроены (блокировка,
заставка, лимит простоя сеанса RDP, keep-alive) и что происходило с
сеансами - блокировка, сон, отключение сеанса и его причина. Так видно,
отключается ли сеанс сразу после блокировки по таймеру.
"""

import datetime

from .sysutil import IS_WINDOWS, powershell_json

_TS_POLICY = r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
_RDP_TCP = r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
_SYS_POLICY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
_DESKTOP = r"Control Panel\Desktop"
_DESKTOP_POLICY = r"Software\Policies\Microsoft\Windows\Control Panel\Desktop"

LSM_LOG = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"

EVENT_TEXT = {
    21: "вход в сеанс",
    23: "выход из сеанса",
    24: "сеанс отключён",
    25: "переподключение к сеансу",
    39: "сеанс отключён другим сеансом",
    40: "причина отключения сеанса",
    4800: "компьютер заблокирован",
    4801: "компьютер разблокирован",
    4802: "включилась заставка",
    4803: "заставка выключилась",
    42: "переход в сон",
    107: "выход из сна",
    1: "выход из сна",
}
LOCK_IDS = (4800, 4802, 42)
DISCONNECT_IDS = (24, 39)
# Коды причины из события 40 (ExtendedDisconnectReason)
DISCONNECT_REASON = {
    0: "без дополнительных сведений (обычно обрыв сети или клиент закрыл соединение)",
    1: "отключено программой (API)",
    2: "выход из системы программой (API)",
    3: "истёк лимит простоя сеанса на сервере",
    4: "истёк лимит времени на вход",
    5: "сеанс перехвачен новым подключением",
    6: "на сервере не хватило памяти",
    7: "сервер отклонил подключение",
    9: "у пользователя нет права входа по RDP",
    11: "отключено действием пользователя в сеансе",
    12: "пользователь вышел из системы",
}
# что считать "сразу после блокировки"
LOCK_WINDOW = 180


def _reg(hive, key, name):
    try:
        import winreg
        with winreg.OpenKey(getattr(winreg, hive), key) as k:
            return winreg.QueryValueEx(k, name)[0]
    except Exception:
        return None


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def timers():
    """Таймеры этого ПК. Только Windows, иначе None. Значения в секундах."""
    if not IS_WINDOWS:
        return None

    def first(*vals):
        return next((v for v in vals if v is not None), None)

    def ms(hive, key, name):
        v = _int(_reg(hive, key, name))
        return v // 1000 if v else v

    r = {
        "lock_inactivity": _int(_reg("HKEY_LOCAL_MACHINE", _SYS_POLICY, "InactivityTimeoutSecs")),
        "screensaver_active": first(_reg("HKEY_CURRENT_USER", _DESKTOP_POLICY, "ScreenSaveActive"),
                                    _reg("HKEY_CURRENT_USER", _DESKTOP, "ScreenSaveActive")),
        "screensaver_secure": first(_reg("HKEY_CURRENT_USER", _DESKTOP_POLICY,
                                         "ScreenSaverIsSecure"),
                                    _reg("HKEY_CURRENT_USER", _DESKTOP, "ScreenSaverIsSecure")),
        "screensaver_timeout": _int(first(_reg("HKEY_CURRENT_USER", _DESKTOP_POLICY,
                                               "ScreenSaveTimeOut"),
                                          _reg("HKEY_CURRENT_USER", _DESKTOP,
                                               "ScreenSaveTimeOut"))),
        "rdp_idle": first(ms("HKEY_CURRENT_USER", _TS_POLICY, "MaxIdleTime"),
                          ms("HKEY_LOCAL_MACHINE", _TS_POLICY, "MaxIdleTime"),
                          ms("HKEY_LOCAL_MACHINE", _RDP_TCP, "MaxIdleTime")),
        "rdp_disconnected": first(ms("HKEY_CURRENT_USER", _TS_POLICY, "MaxDisconnectionTime"),
                                  ms("HKEY_LOCAL_MACHINE", _TS_POLICY, "MaxDisconnectionTime"),
                                  ms("HKEY_LOCAL_MACHINE", _RDP_TCP, "MaxDisconnectionTime")),
        "rdp_session": first(ms("HKEY_CURRENT_USER", _TS_POLICY, "MaxConnectionTime"),
                             ms("HKEY_LOCAL_MACHINE", _TS_POLICY, "MaxConnectionTime"),
                             ms("HKEY_LOCAL_MACHINE", _RDP_TCP, "MaxConnectionTime")),
        "keepalive": _int(_reg("HKEY_LOCAL_MACHINE", _TS_POLICY, "KeepAliveEnable")),
        "keepalive_min": _int(_reg("HKEY_LOCAL_MACHINE", _TS_POLICY, "KeepAliveInterval")),
    }
    r["sleep_ac"], r["sleep_dc"] = _sleep_timeouts()
    return r


_PS_SLEEP = r"""
$o = powercfg /query SCHEME_CURRENT SUB_SLEEP STANDBYIDLE
$v = @($o | Select-String '0x[0-9a-fA-F]{8}' | ForEach-Object { $_.Matches[-1].Value })
@{ ac = $v[-2]; dc = $v[-1] } | ConvertTo-Json -Compress
"""


def _sleep_timeouts():
    """Через сколько секунд простоя ПК засыпает: (от сети, от батареи)."""
    d = powershell_json(_PS_SLEEP, timeout=15)
    if not isinstance(d, dict):
        return None, None
    res = []
    for k in ("ac", "dc"):
        try:
            res.append(int(d.get(k), 16))
        except (TypeError, ValueError):
            res.append(None)
    return tuple(res)


def _dur(sec):
    if sec % 3600 == 0:
        return "%d ч" % (sec // 3600)
    if sec % 60 == 0:
        return "%d мин" % (sec // 60)
    return "%d с" % sec


def describe_timers(t):
    """[(текст, важно ли для обрывов RDP)] - понятное описание таймеров."""
    if not t:
        return []
    out = []
    if t.get("lock_inactivity"):
        out.append(("блокировка по простою (политика): через %s" % _dur(t["lock_inactivity"]),
                    False))
    if str(t.get("screensaver_active")) == "1" and t.get("screensaver_timeout"):
        out.append(("заставка через %s%s" % (
            _dur(t["screensaver_timeout"]),
            ", с блокировкой" if str(t.get("screensaver_secure")) == "1" else ""), False))
    if t.get("rdp_idle"):
        out.append(("лимит простоя сеанса RDP: через %s сервер отключает сеанс"
                    % _dur(t["rdp_idle"]), True))
    if t.get("rdp_session"):
        out.append(("лимит длительности сеанса RDP: %s" % _dur(t["rdp_session"]), True))
    if t.get("rdp_disconnected"):
        out.append(("отключённый сеанс завершается через %s" % _dur(t["rdp_disconnected"]),
                    False))
    for k, name in (("sleep_ac", "от сети"), ("sleep_dc", "от батареи")):
        if t.get(k):
            out.append(("сон через %s простоя (%s)" % (_dur(t[k]), name), True))
    if t.get("keepalive") == 1:
        out.append(("keep-alive RDP включён%s" % (
            ", раз в %d мин" % t["keepalive_min"] if t.get("keepalive_min") else ""), False))
    return out


_PS_EVENTS = r"""
$start = (Get-Date).AddMinutes(-%d)
$q = @(
  @{LogName='%s'; Id=21,23,24,25,39,40; StartTime=$start},
  @{LogName='Security'; Id=4800,4801,4802,4803; StartTime=$start},
  @{LogName='System'; ProviderName='Microsoft-Windows-Kernel-Power'; Id=42,107; StartTime=$start},
  @{LogName='System'; ProviderName='Microsoft-Windows-Power-Troubleshooter'; Id=1; StartTime=$start})
$r = @{ events = @(); denied = @() }
foreach ($f in $q) {
  try {
    $r.events += @(Get-WinEvent -FilterHashtable $f -MaxEvents 300 -ErrorAction Stop | ForEach-Object {
      @{ time = $_.TimeCreated.ToString('o'); id = $_.Id; log = $f.LogName;
         props = @($_.Properties | ForEach-Object { [string]$_.Value }) } })
  } catch {
    if ([string]$_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') { $r.denied += $f.LogName }
  }
}
$r | ConvertTo-Json -Depth 4 -Compress
"""


def events(minutes=1440):
    """События блокировки, сна и сеансов за minutes минут: {"events": [...], "denied": [...]}.

    Журнал Security (блокировка) читается только с правами администратора."""
    if not IS_WINDOWS:
        return None
    d = powershell_json(_PS_EVENTS % (int(minutes), LSM_LOG), timeout=40)
    if not isinstance(d, dict):
        return {"events": [], "denied": []}
    evs = d.get("events") or []
    if isinstance(evs, dict):
        evs = [evs]
    for e in evs:
        parse_event(e)
    evs.sort(key=lambda e: e.get("time") or "")
    denied = d.get("denied") or []
    return {"events": evs, "denied": [denied] if isinstance(denied, str) else denied}


def parse_event(e):
    i = e.get("id")
    props = e.get("props") or []
    e["text"] = EVENT_TEXT.get(i, "событие %s" % i)
    if i == 40 and len(props) >= 2:
        code = _int(props[1])
        e["reason"] = code
        e["text"] = "сеанс %s отключён: %s (код %s)" % (
            props[0], DISCONNECT_REASON.get(code, "неизвестная причина"), code)
    elif i in (21, 23, 24, 25) and len(props) >= 3:
        e["user"], e["session"], e["source"] = props[0], props[1], props[2]
        e["text"] += " %s (сеанс %s, %s)" % (props[0], props[1], props[2])
    return e


def _ts(iso):
    """'2026-10-14T13:18:38.1234567+03:00' -> epoch (по местному времени события)."""
    try:
        return datetime.datetime.fromisoformat(iso[:19]).timestamp() if iso else None
    except (ValueError, OSError, OverflowError):
        return None


def correlate(evs, window=LOCK_WINDOW):
    """Отключения сеанса RDP и что было перед ними.

    Возвращает [{"time", "text", "after": "компьютер заблокирован" | None,
    "gap": секунд после блокировки/сна, "reason": код из события 40}]."""
    res = []
    for i, e in enumerate(evs):
        if e.get("id") not in DISCONNECT_IDS:
            continue
        if e.get("source") and e["source"].upper() == "LOCAL":
            continue  # отключение сеанса на самом ПК, а не по RDP
        t = _ts(e.get("time"))
        reason = next((x.get("reason") for x in evs
                       if x.get("id") == 40 and t is not None
                       and abs((_ts(x.get("time")) or 0) - t) <= 5), None)
        prev = [x for x in evs[:i] if x.get("id") in LOCK_IDS and t is not None
                and 0 <= t - (_ts(x.get("time")) or 0) <= window]
        item = {"time": e.get("time"), "text": e["text"], "reason": reason,
                "after": None, "gap": None}
        if prev:
            item["after"] = prev[-1]["text"]
            item["gap"] = int(t - _ts(prev[-1]["time"]))
        res.append(item)
    return res


def summarize(timers_, ev):
    """(статус, текст) для проверки «Сеансы RDP на этом ПК»."""
    if ev is None:
        return None
    discs = correlate(ev.get("events") or [])
    locked = [d for d in discs if d["after"]]
    idle = [d for d in discs if d["reason"] == 3]
    parts = []
    if discs:
        parts.append("отключений сеанса RDP за сутки: %d" % len(discs))
    if locked:
        parts.append("из них сразу после блокировки, заставки или сна: %d (%s)" % (
            len(locked), "; ".join("%s через %d с после «%s»" % (
                d["time"][11:19], d["gap"], d["after"]) for d in locked[-4:])))
    if idle:
        parts.append("по лимиту простоя сервера: %d" % len(idle))
    if "Security" in ev.get("denied", []):
        parts.append("журнал блокировок (Security) не прочитан: запустите IPInfo от имени "
                     "администратора")
    if not parts:
        return "ok", "отключений сеанса RDP за сутки не было"
    return ("warn" if locked or idle else "info"), "; ".join(parts)
