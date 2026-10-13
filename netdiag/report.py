# -*- coding: utf-8 -*-
"""Журнал программы, текстовый вид проверки и zip-отчёт для отправки."""

import datetime
import glob
import json
import logging
import logging.handlers
import os
import platform
import socket
import zipfile

from . import __version__
from .sysutil import data_dir
from . import winsys

MARK = {"ok": "[ OK ]", "warn": "[ !! ]", "fail": "[FAIL]", "info": "[ -- ]"}
MAX_LOG_FILE = 5 * 1024 * 1024  # из логов VPN-клиента берём последние 5 МБ файла
MAX_LOG_FILES = 20

log = logging.getLogger("ipinfo")


def logs_dir():
    path = os.path.join(data_dir(), "logs")
    os.makedirs(path, exist_ok=True)
    return path


def reports_dir():
    path = os.path.join(data_dir(), "reports")
    os.makedirs(path, exist_ok=True)
    return path


def setup_logging():
    """Журнал программы: ipinfo.log, до 5 файлов по 1 МБ."""
    if log.handlers:
        return
    log.setLevel(logging.INFO)
    try:
        h = logging.handlers.RotatingFileHandler(
            os.path.join(logs_dir(), "ipinfo.log"), maxBytes=1024 * 1024,
            backupCount=5, encoding="utf-8")
        h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        log.addHandler(h)
    except OSError:
        log.addHandler(logging.NullHandler())


def save_check(data):
    """Дописывает результат проверки в checks.jsonl (одна строка JSON на проверку)."""
    try:
        with open(os.path.join(logs_dir(), "checks.jsonl"), "a", encoding="utf-8") as f:
            f.write(json.dumps(data, ensure_ascii=False, default=str) + "\n")
    except OSError as e:
        log.warning("не удалось записать checks.jsonl: %s", e)
    for line in data.get("verdict", []):
        log.info("ИТОГ: %s", line)
    for c in data.get("checks", []):
        if c["status"] in ("warn", "fail"):
            log.info("%s %s / %s: %s", MARK[c["status"]], c["group"], c["name"], c["summary"])


def format_check(c):
    return "%s %s: %s" % (MARK.get(c["status"], "[    ]"), c["name"], c["summary"])


def format_text(data):
    """Проверка в виде текста для человека."""
    out = ["IPInfo %s - проверка сети" % data.get("version", __version__),
           "Компьютер: %s    %s" % (data.get("host"), data.get("os")),
           "Время: %s    длительность %s с" % (data.get("time"), data.get("duration_sec")),
           "", "ИТОГ"]
    out += ["  * " + v for v in data.get("verdict", [])]
    group = None
    for c in data.get("checks", []):
        if c["group"] != group:
            group = c["group"]
            out += ["", group.upper()]
        out.append("  " + format_check(c))
    out.append("")
    out.append("АДАПТЕРЫ")
    for a in data.get("adapters", []):
        if a.get("loopback"):
            continue
        out.append("  %s [%s] %s - %s" % (a["name"], a["status"], a["type"], a["description"]))
        if a["ipv4"] or a["ipv6"]:
            out.append("    IPv4 %s; шлюз %s; DNS %s" % (
                ", ".join(a["ipv4"]) or "-", ", ".join(a["gateway"]) or "-",
                ", ".join(a["dns"]) or "-"))
        out.append("    MAC %s, MTU %s, скорость %s" % (a["mac"], a["mtu"], a["speed"]))
    return "\n".join(out) + "\n"


def _add_vpn_logs(z, logs_cfg):
    """Добавляет журналы VPN-клиентов из раздела [logs]. Возвращает список заметок."""
    notes = []
    for name, pattern in logs_cfg.items():
        if os.path.isdir(pattern):
            pattern = os.path.join(pattern, "*")
        files = [f for f in glob.glob(pattern) if os.path.isfile(f)]
        files.sort(key=lambda f: os.path.getmtime(f), reverse=True)
        if not files:
            notes.append("%s: файлов по маске %s не найдено" % (name, pattern))
            continue
        for f in files[:MAX_LOG_FILES]:
            try:
                size = os.path.getsize(f)
                with open(f, "rb") as fh:
                    if size > MAX_LOG_FILE:
                        fh.seek(size - MAX_LOG_FILE)
                    z.writestr("vpn_logs/%s/%s" % (name, os.path.basename(f)), fh.read())
            except OSError as e:
                notes.append("%s: %s - %s" % (name, f, e))
    return notes


def build_zip(data, cfg, path=None):
    """Собирает отчёт в zip: проверка, журналы, системные выводы, логи VPN.

    Возвращает путь к файлу.
    """
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    host = "".join(ch for ch in socket.gethostname() if ch.isalnum() or ch in "-_") or "pc"
    path = path or os.path.join(reports_dir(), "ipinfo-%s-%s.zip" % (host, stamp))
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("report.txt", format_text(data))
        z.writestr("report.json", json.dumps(data, ensure_ascii=False, indent=2, default=str))
        for name, text in winsys.system_dumps().items():
            z.writestr("system/" + name, text)
        if cfg.get("path") and os.path.exists(cfg["path"]):
            z.write(cfg["path"], "ipinfo.ini")
        for f in sorted(glob.glob(os.path.join(logs_dir(), "*"))):
            if os.path.isfile(f):
                z.write(f, "ipinfo_logs/" + os.path.basename(f))
        notes = _add_vpn_logs(z, cfg.get("logs", {}))
        info = ["IPInfo %s" % __version__, "Собран: %s" % stamp,
                "Компьютер: %s" % socket.gethostname(), "ОС: %s" % platform.platform(),
                "Пользователь: %s" % (os.environ.get("USERNAME") or os.environ.get("USER", ""))]
        if not cfg.get("logs"):
            notes.append("пути к журналам VPN-клиентов не заданы (раздел [logs] в ipinfo.ini)")
        z.writestr("about.txt", "\n".join(info + [""] + notes) + "\n")
    log.info("отчёт сохранён: %s", path)
    return path
