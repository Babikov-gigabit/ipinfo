# -*- coding: utf-8 -*-
"""Клиент «Континент ZTN» (Код Безопасности): где установлен, какие серверы
прописаны в его настройках, где лежат его журналы и утилита сбора диагностики.

Формат VPNConfig.json не документирован, поэтому из него берутся все строки,
похожие на адрес сервера (IP или имя с точкой, с портом или без).
"""

import glob
import ipaddress
import json
import os
import re

from .sysutil import IS_WINDOWS

INSTALL_NAMES = ("Continent ZTN Client", "Continent TLS Client", "Continent ZTN")
CONFIG_FILES = ("VPNConfig.json",)
COLLECTOR = "LogCollector.exe"
# служебные имена, которые встречаются в настройках, но не являются серверами
_NOT_HOSTS = re.compile(r"\.(json|xml|exe|dll|log|txt|cer|crt|pem|p7b|xsl|ini)$|"
                        r"(^|\.)(microsoft|windows|securitycode|w3)\.(com|ru|org)$", re.I)
_HOST_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.I)


def _env(name, default=""):
    return os.environ.get(name, default)


def install_dir():
    """Папка установки клиента или None."""
    roots = [_env("ProgramFiles", r"C:\Program Files"), _env("ProgramW6432"),
             _env("ProgramFiles(x86)")]
    for root in roots:
        for name in INSTALL_NAMES:
            path = os.path.join(root, "Security Code", name) if root else ""
            if path and os.path.isdir(path):
                return path
    if IS_WINDOWS:
        return _install_from_registry()
    return None


def _install_from_registry():
    try:
        import winreg
    except ImportError:
        return None
    key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
        try:
            root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0,
                                  winreg.KEY_READ | view)
        except OSError:
            continue
        with root:
            for i in range(winreg.QueryInfoKey(root)[0]):
                try:
                    with winreg.OpenKey(root, winreg.EnumKey(root, i)) as k:
                        name = winreg.QueryValueEx(k, "DisplayName")[0]
                        if "континент" in name.lower() or "continent" in name.lower():
                            loc = winreg.QueryValueEx(k, "InstallLocation")[0]
                            if loc and os.path.isdir(loc):
                                return loc
                except OSError:
                    continue
    return None


def log_dirs():
    """Папки, где клиент и его утилиты хранят журналы и данные."""
    cands = []
    for base in (_env("LOCALAPPDATA"), _env("APPDATA"), _env("ProgramData")):
        if not base:
            continue
        for pat in ("Security Code", "SecurityCode", "ContinentZTNClient", "Continent*"):
            cands += glob.glob(os.path.join(base, pat))
    windir = _env("WINDIR", r"C:\Windows")
    cands.append(os.path.join(windir, "System32", "config", "systemprofile", "AppData",
                              "Local", "Security Code"))
    seen, res = set(), []
    for c in cands:
        key = os.path.normcase(os.path.abspath(c))
        if key not in seen and os.path.isdir(c):
            seen.add(key)
            res.append(c)
    return res


def log_files(max_files=40):
    """Журналы клиента: *.log/*.txt и подобные из log_dirs(), свежие первыми."""
    files = []
    for d in log_dirs():
        for root, _dirs, names in os.walk(d):
            for n in names:
                if re.search(r"\.(log|txt|json|xml|trace)(\.\d+)?$", n, re.I) or "log" in n.lower():
                    files.append(os.path.join(root, n))
    files = [f for f in files if os.path.isfile(f)]
    files.sort(key=lambda f: os.path.getmtime(f), reverse=True)
    return files[:max_files]


def collector_path():
    d = install_dir()
    path = os.path.join(d, COLLECTOR) if d else None
    return path if path and os.path.isfile(path) else None


def _endpoint(text):
    """'host', 'host:443', 'https://host:443/path', '1.2.3.4' -> (host, port|None) или None."""
    t = text.strip()
    t = re.sub(r"^[a-z][a-z0-9+.-]*://", "", t, flags=re.I).split("/")[0]
    if not t or " " in t or len(t) > 253:
        return None
    port = None
    m = re.match(r"^(.+):(\d{1,5})$", t)
    if m:
        t, port = m.group(1), int(m.group(2))
    try:
        ipaddress.IPv4Address(t)
        return t, port
    except ValueError:
        pass
    if _HOST_RE.match(t) and not _NOT_HOSTS.search(t):
        return t.lower(), port
    return None


def servers_from_config(data):
    """Все адреса серверов из разобранного JSON: [{'host', 'port'}] без повторов."""
    found = []

    def walk(obj, port_hint=None):
        if isinstance(obj, dict):
            port = None
            for k, v in obj.items():
                if "port" in str(k).lower():
                    try:
                        port = int(v)
                    except (TypeError, ValueError):
                        pass
            for v in obj.values():
                walk(v, port or port_hint)
        elif isinstance(obj, list):
            for v in obj:
                walk(v, port_hint)
        elif isinstance(obj, str):
            ep = _endpoint(obj)
            if ep:
                found.append({"host": ep[0], "port": ep[1] or port_hint or 443})
    walk(data)
    res = []
    for f in found:
        if f not in res:
            res.append(f)
    return res


def config_files():
    d = install_dir()
    if not d:
        return []
    return [os.path.join(d, n) for n in CONFIG_FILES if os.path.isfile(os.path.join(d, n))]


def info():
    """Сводка о клиенте: папка, серверы из настроек, журналы, утилита диагностики."""
    d = install_dir()
    res = {"install": d, "servers": [], "config_error": None, "log_dirs": log_dirs(),
           "collector": collector_path()}
    for path in config_files():
        try:
            with open(path, encoding="utf-8-sig") as f:
                res["servers"] += [s for s in servers_from_config(json.load(f))
                                   if s not in res["servers"]]
        except (OSError, ValueError) as e:
            res["config_error"] = "%s: %s" % (os.path.basename(path), e)
    return res
