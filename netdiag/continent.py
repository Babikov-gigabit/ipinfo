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


def _port_of(d):
    """Порт из словаря: tcpPort важнее прочих (в профиле есть и udpPort)."""
    keys = {str(k).lower(): v for k, v in d.items()}
    for k in ["tcpport", "port"] + [k for k in keys if "port" in k and "udp" not in k]:
        try:
            return int(keys[k])
        except (KeyError, TypeError, ValueError):
            continue
    return None


def profiles_from_data(data, source=""):
    """Профили подключения: словари со списком connections [{host, tcpPort, ...}].

    Порядок адресов важен: клиент подключается к первому, а к следующему
    переходит, только когда исчерпает попытки на предыдущем."""
    found = []

    def walk(obj):
        if isinstance(obj, dict):
            conns = obj.get("connections")
            if isinstance(conns, list) and any(isinstance(c, dict) and c.get("host")
                                               for c in conns):
                servers = []
                for c in conns:
                    if isinstance(c, dict) and c.get("host"):
                        servers.append({"host": str(c["host"]).strip(),
                                        "port": _port_of(c) or 443,
                                        "udp_port": c.get("udpPort")})
                found.append({"name": obj.get("name") or "?", "servers": servers,
                              "type": obj.get("profileType"), "source": source})
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)
    walk(data)
    return found


def _json_files(max_size=2 * 1024 * 1024):
    dirs = ([install_dir()] if install_dir() else []) + log_dirs()
    for d in dirs:
        for root, _dirs, names in os.walk(d):
            for n in names:
                if n.lower().endswith(".json"):
                    path = os.path.join(root, n)
                    try:
                        if os.path.getsize(path) <= max_size:
                            yield path
                    except OSError:
                        continue


def profiles():
    """Профили из всех json-файлов клиента (настройки, профили, экспорт)."""
    res = []
    for path in _json_files():
        try:
            with open(path, encoding="utf-8-sig") as f:
                data = json.load(f)
        except (OSError, ValueError):
            continue
        for p in profiles_from_data(data, path):
            if not any(p["name"] == q["name"] and p["servers"] == q["servers"] for q in res):
                res.append(p)
    return res


def servers_from_config(data):
    """Все адреса серверов из разобранного JSON: [{'host', 'port'}] без повторов."""
    found = []

    def walk(obj, port_hint=None):
        if isinstance(obj, dict):
            port = _port_of(obj)
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
           "collector": collector_path(), "profiles": []}
    for path in config_files():
        try:
            with open(path, encoding="utf-8-sig") as f:
                res["servers"] += [s for s in servers_from_config(json.load(f))
                                   if s not in res["servers"]]
        except (OSError, ValueError) as e:
            res["config_error"] = "%s: %s" % (os.path.basename(path), e)
    try:
        res["profiles"] = profiles()
    except Exception as e:
        res["config_error"] = "профили: %s" % e
    # адреса из профилей - первыми и в их порядке
    ordered = [{"host": x["host"].lower(), "port": x["port"]}
               for p in res["profiles"] for x in p["servers"]]
    res["servers"] = [x for i, x in enumerate(ordered) if x not in ordered[:i]] + \
        [x for x in res["servers"] if x not in ordered]
    return res
