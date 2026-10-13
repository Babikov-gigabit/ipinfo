# -*- coding: utf-8 -*-
"""Настройки проверок: ipinfo.ini рядом с exe."""

import configparser
import os
import re

from .sysutil import app_dir, data_dir

CONFIG_NAME = "ipinfo.ini"

SAMPLE = """\
; Настройки IPInfo. Строки, начинающиеся с ';', - комментарии.
; Все адреса из списков проверяются одновременно.

[vpn]
; VPN-серверы: имя = адрес:порт/протокол (tcp или udp). Сколько угодно строк.
; Для tcp проверяется, открыт ли порт. Для udp - только имя и ping.
; continent_main = vpn1.example.ru:443/tcp
; continent_res  = vpn2.example.ru:443/tcp
; openconnect    = oc.example.ru:443/tcp

[internal]
; Адреса внутри корпоративной сети, доступные только через туннель.
; dc   = 10.0.0.1
; mail = 10.0.5.20

[internet]
; Адреса для проверки интернета под VPN (через запятую).
targets = 1.1.1.1, 8.8.8.8, ya.ru

[tunnel]
; Сеть, адрес из которой получает VPN-адаптер.
network = 10.0.0.0/8
; Части названия или описания адаптера, по которым узнаётся VPN-клиент.
continent = Continent, Континент, Код Безопасности, Security Code, ZTN
openconnect = OpenConnect, Wintun, TAP-Windows

[rdp]
; Проверять ли готовность ПК принимать входящие RDP-подключения через туннель.
enabled = yes
; Сети, из которых администраторы подключаются по RDP (через запятую).
; Проверяется, что ответы ПК в эти сети уйдут в туннель, а не в домашнюю сеть.
; sources = 10.1.2.0/24

[logs]
; Папки или файлы с журналами VPN-клиентов, которые добавятся в отчёт.
; Можно использовать %ProgramData%, %LOCALAPPDATA% и маски *.log.
; continent = %ProgramData%\\Security Code\\Continent\\*.log
; openconnect = %LOCALAPPDATA%\\OpenConnect-GUI\\*.log
"""


def config_path():
    """ipinfo.ini рядом с exe; если туда нельзя писать - в %LOCALAPPDATA%\\IPInfo."""
    near = os.path.join(app_dir(), CONFIG_NAME)
    if os.path.exists(near):
        return near
    fallback = os.path.join(data_dir(), CONFIG_NAME)
    if os.path.exists(fallback):
        return fallback
    return near


def _split(value):
    return [x.strip() for x in re.split(r"[,;]", value or "") if x.strip()]


def parse_endpoint(value):
    """'host:443/tcp' -> (host, 443, 'tcp'). Порт по умолчанию 443/tcp."""
    v = value.strip()
    proto = "tcp"
    m = re.match(r"^(.*)/(tcp|udp)$", v, re.I)
    if m:
        v, proto = m.group(1), m.group(2).lower()
    port = 443
    m = re.match(r"^\[?([^\]]+?)\]?:(\d+)$", v)
    if m:
        v, port = m.group(1), int(m.group(2))
    return v.strip(), port, proto


def ensure_config():
    """Создаёт пример настроек, если файла нет. Возвращает путь."""
    path = config_path()
    if os.path.exists(path):
        return path
    for target in (path, os.path.join(data_dir(), CONFIG_NAME)):
        try:
            with open(target, "w", encoding="utf-8-sig") as f:
                f.write(SAMPLE)
            return target
        except OSError:
            continue
    return path


def load(path=None):
    """Читает настройки. Без файла работает с настройками по умолчанию."""
    cp = configparser.ConfigParser(inline_comment_prefixes=(";", "#"), interpolation=None)
    cp.optionxform = str  # сохранять регистр имён
    cp.read_string(SAMPLE)
    path = path or config_path()
    if os.path.exists(path):
        # Пользовательский файл полностью заменяет списки серверов и адресов
        for sec in ("vpn", "internal", "logs"):
            cp.remove_section(sec)
            cp.add_section(sec)
        with open(path, encoding="utf-8-sig") as f:
            cp.read_file(f)

    vpn = []
    for name, value in cp.items("vpn"):
        host, port, proto = parse_endpoint(value)
        if host:
            vpn.append({"name": name, "host": host, "port": port, "proto": proto})

    return {
        "path": path if os.path.exists(path) else None,
        "vpn": vpn,
        "internal": [{"name": n, "host": v.strip()} for n, v in cp.items("internal") if v.strip()],
        "internet": _split(cp.get("internet", "targets", fallback="")),
        "tunnel_network": cp.get("tunnel", "network", fallback="10.0.0.0/8").strip(),
        "patterns": {
            "Континент": _split(cp.get("tunnel", "continent", fallback="")),
            "OpenConnect": _split(cp.get("tunnel", "openconnect", fallback="")),
        },
        "rdp": cp.getboolean("rdp", "enabled", fallback=True),
        "rdp_sources": _split(cp.get("rdp", "sources", fallback="")),
        "logs": {n: os.path.expandvars(v.strip()) for n, v in cp.items("logs") if v.strip()},
    }
