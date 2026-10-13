# -*- coding: utf-8 -*-
"""Сведения Windows: RDP, профили сетей, брандмауэр, Wi-Fi, системные команды.

Всё читается без прав администратора.
"""

import ctypes
import re

from .sysutil import IS_WINDOWS, powershell_json, run

# --------------------------------------------------------------------------
# RDP
# --------------------------------------------------------------------------
_TS_KEY = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
_RDP_TCP_KEY = _TS_KEY + r"\WinStations\RDP-Tcp"
_SERVICE_STATE = {1: "остановлена", 2: "запускается", 3: "останавливается",
                  4: "работает", 5: "возобновляется", 6: "приостанавливается",
                  7: "приостановлена"}
# Редакции Windows без сервера RDP (к ним нельзя подключиться по RDP)
HOME_EDITIONS = ("Core", "CoreN", "CoreSingleLanguage", "CoreCountrySpecific")


def _reg(key, name):
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key) as k:
            return winreg.QueryValueEx(k, name)[0]
    except Exception:
        return None


def _service_state(name):
    """Состояние службы Windows через Service Control Manager (не зависит от языка)."""
    class SERVICE_STATUS(ctypes.Structure):
        _fields_ = [(n, ctypes.c_uint32) for n in (
            "dwServiceType", "dwCurrentState", "dwControlsAccepted", "dwWin32ExitCode",
            "dwServiceSpecificExitCode", "dwCheckPoint", "dwWaitHint")]

    adv = ctypes.windll.advapi32
    adv.OpenSCManagerW.restype = ctypes.c_void_p
    adv.OpenServiceW.restype = ctypes.c_void_p
    adv.OpenServiceW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32]
    adv.QueryServiceStatus.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    adv.CloseServiceHandle.argtypes = [ctypes.c_void_p]
    scm = adv.OpenSCManagerW(None, None, 0x0001)  # SC_MANAGER_CONNECT
    if not scm:
        return None
    try:
        svc = adv.OpenServiceW(scm, name, 0x0004)  # SERVICE_QUERY_STATUS
        if not svc:
            return None
        try:
            st = SERVICE_STATUS()
            if not adv.QueryServiceStatus(svc, ctypes.byref(st)):
                return None
            return st.dwCurrentState
        finally:
            adv.CloseServiceHandle(svc)
    finally:
        adv.CloseServiceHandle(scm)


def parse_listeners(netstat_out, port):
    """Адреса, на которых слушается TCP-порт, из вывода `netstat -ano -p TCP`.

    Состояние LISTENING на русской Windows называется иначе, поэтому
    слушающие строки узнаём по удалённому адресу 0.0.0.0:0.
    """
    res = []
    for line in netstat_out.splitlines():
        p = line.split()
        if len(p) >= 4 and p[0].upper() == "TCP" and p[2] in ("0.0.0.0:0", "[::]:0"):
            host, _, lport = p[1].rpartition(":")
            if lport == str(port):
                res.append(host)
    return res


def rdp_info():
    """Готов ли ПК принимать RDP. Только Windows."""
    if not IS_WINDOWS:
        return None
    edition = _reg(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "EditionID")
    deny = _reg(_TS_KEY, "fDenyTSConnections")
    port = _reg(_RDP_TCP_KEY, "PortNumber") or 3389
    nla = _reg(_RDP_TCP_KEY, "UserAuthentication")
    try:
        state = _service_state("TermService")
    except Exception:
        state = None
    listen = parse_listeners(run(["netstat", "-ano", "-p", "TCP"]), port)
    return {
        "edition": edition,
        "home_edition": edition in HOME_EDITIONS,
        "enabled": deny == 0 if deny is not None else None,
        "port": port,
        "nla": bool(nla) if nla is not None else None,
        "service_state": state,
        "service_text": _SERVICE_STATE.get(state, "неизвестно"),
        "listening_on": listen,
    }


# --------------------------------------------------------------------------
# Профили сетей и брандмауэр (PowerShell, вывод в JSON)
# --------------------------------------------------------------------------
NET_CATEGORY = {0: "Общедоступная", 1: "Частная", 2: "Доменная"}
_FW_PROFILE_BIT = {"Общедоступная": 4, "Частная": 2, "Доменная": 1}

_PS_FIREWALL = r"""
$r = @{}
$r.profiles = @(Get-NetConnectionProfile | ForEach-Object {
  @{ alias = $_.InterfaceAlias; index = $_.InterfaceIndex; name = $_.Name;
     category = [int]$_.NetworkCategory; ipv4 = [int]$_.IPv4Connectivity } })
$r.firewall = @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {
  @{ name = [string]$_.Name; enabled = [string]$_.Enabled;
     inbound = [string]$_.DefaultInboundAction } })
$r.rdp_rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Group '@FirewallAPI.dll,-28752' | ForEach-Object {
  @{ name = $_.DisplayName; enabled = [string]$_.Enabled; profile = [int]$_.Profile;
     direction = [string]$_.Direction; action = [string]$_.Action } })
$r | ConvertTo-Json -Depth 4 -Compress
"""


def firewall_info():
    """Профили сетей адаптеров, состояние брандмауэра и правила RDP."""
    if not IS_WINDOWS:
        return None
    data = powershell_json(_PS_FIREWALL)
    if not isinstance(data, dict):
        return None
    for p in data.get("profiles") or []:
        p["category_text"] = NET_CATEGORY.get(p.get("category"), "?")
    return data


def rdp_allowed_for(category_text, fw):
    """Разрешено ли входящее RDP правилами брандмауэра для профиля сети.

    True / False, либо None, если правил прочитать не удалось.
    """
    if not fw or not fw.get("rdp_rules"):
        return None
    bit = _FW_PROFILE_BIT.get(category_text, 0)
    for r in fw["rdp_rules"]:
        if r.get("enabled") != "True" or r.get("direction") != "Inbound" \
                or r.get("action") != "Allow":
            continue
        prof = r.get("profile") or 0
        if prof == 0 or prof & bit:  # 0 = Any
            return True
    return False


def firewall_enabled_for(category_text, fw):
    names = {"Общедоступная": "Public", "Частная": "Private", "Доменная": "Domain"}
    for p in (fw or {}).get("firewall") or []:
        if p.get("name") == names.get(category_text):
            return p.get("enabled") == "True"
    return None


# --------------------------------------------------------------------------
# Wi-Fi
# --------------------------------------------------------------------------
def parse_wlan(out):
    """Разбор `netsh wlan show interfaces` (русская и английская Windows)."""
    res = {}
    for line in out.splitlines():
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key, val = key.strip(), val.strip()
        k = key.lower()
        if k == "ssid":
            res["ssid"] = val
        elif k == "bssid" or k == "ap bssid":
            res["bssid"] = line.split(":", 1)[1].strip()
        elif k in ("signal", "сигнал"):
            m = re.match(r"(\d+)", val)
            if m:
                res["signal_pct"] = int(m.group(1))
        elif k in ("channel", "канал"):
            m = re.match(r"(\d+)", val)
            if m:
                res["channel"] = int(m.group(1))
        elif k in ("radio type", "тип радио", "тип радиомодуля"):
            res["radio"] = val
        elif k in ("band", "диапазон"):
            res["band"] = val
        elif k.startswith("receive rate") or k.startswith("скорость приема") \
                or k.startswith("скорость приёма"):
            res["rx_mbps"] = val
        elif k in ("state", "состояние"):
            res.setdefault("state", val)
    return res


def wifi_info():
    if IS_WINDOWS:
        out = run(["netsh", "wlan", "show", "interfaces"])
        info = parse_wlan(out)
        return info if info.get("ssid") else None
    return None


# --------------------------------------------------------------------------
# Сырые выводы системных команд для отчёта
# --------------------------------------------------------------------------
def system_dumps():
    """Выводы стандартных команд: прикладываются к отчёту как есть."""
    if IS_WINDOWS:
        cmds = {
            "ipconfig_all.txt": ["ipconfig", "/all"],
            "route_print.txt": ["route", "print"],
            "netsh_wlan_interfaces.txt": ["netsh", "wlan", "show", "interfaces"],
            "netsh_winhttp_proxy.txt": ["netsh", "winhttp", "show", "proxy"],
            "netstat_ano.txt": ["netstat", "-ano"],
            "arp_a.txt": ["arp", "-a"],
        }
    else:
        cmds = {
            "ip_addr.txt": ["ip", "addr"],
            "ip_route.txt": ["ip", "route"],
            "resolv_conf.txt": ["cat", "/etc/resolv.conf"],
        }
    return {name: run(cmd, timeout=30) for name, cmd in cmds.items()}
