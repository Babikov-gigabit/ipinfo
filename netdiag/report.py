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
from . import continent, winsys

MARK = {"ok": "[ OK ]", "warn": "[ !! ]", "fail": "[FAIL]", "info": "[ -- ]"}
MAX_LOG_FILE = 5 * 1024 * 1024  # из логов VPN-клиента берём последние 5 МБ файла
MAX_LOG_FILES = 20
MAX_CONTINENT_LOGS = 30 * 1024 * 1024  # всего из журналов Континента

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


STATUS_RU = {"ok": ("норма", "#1a7f37", "#e6f4ea"), "warn": ("внимание", "#9a6700", "#fff4d6"),
             "fail": ("ошибка", "#c62828", "#fde7e7"), "info": ("сведения", "#57606a", "#f0f2f4")}


def _esc(text):
    import html
    return html.escape(str(text if text is not None else ""))


def format_html(data, events=None, monitor_summary=None):
    """Отчёт для человека: открывается в браузере, сверху - итог простыми словами."""
    checks = data.get("checks", [])
    counts = {k: sum(1 for c in checks if c["status"] == k) for k in STATUS_RU}
    bad = counts["fail"] > 0
    out = ["<!doctype html><html lang='ru'><head><meta charset='utf-8'>",
           "<title>Отчёт о сети - %s</title>" % _esc(data.get("host")),
           "<style>body{font:15px/1.5 'Segoe UI',Arial,sans-serif;margin:0;background:#f6f7f9;"
           "color:#1f2328}main{max-width:900px;margin:0 auto;padding:24px}"
           "h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 8px}"
           ".meta{color:#57606a;font-size:13px}.box{background:#fff;border-radius:10px;"
           "padding:16px 20px;margin-top:16px;box-shadow:0 1px 3px rgba(0,0,0,.08)}"
           ".verdict li{margin:6px 0;font-size:16px}table{width:100%;border-collapse:collapse}"
           "td{padding:7px 8px;border-top:1px solid #eaecef;vertical-align:top}"
           ".st{white-space:nowrap;font-size:12px;font-weight:600;border-radius:10px;"
           "padding:2px 8px}.n{white-space:nowrap;color:#57606a}.ev td{font-size:13px}"
           ".big{font-size:18px;font-weight:600}table{table-layout:fixed}.c1{width:90px}"
           ".n{width:210px}</style></head><body><main>",
           "<h1>Отчёт о сети и VPN</h1>",
           "<div class='meta'>Компьютер: <b>%s</b> · %s · %s · IPInfo %s</div>" % (
               _esc(data.get("host")), _esc(data.get("time")), _esc(data.get("os")),
               _esc(data.get("version", __version__))),
           "<div class='box'><div class='big' style='color:%s'>%s</div>" % (
               "#c62828" if bad else "#1a7f37",
               "Найдены проблемы" if bad else "Серьёзных проблем не найдено"),
           "<div class='meta'>Ошибок: %d · предупреждений: %d · в норме: %d</div>" % (
               counts["fail"], counts["warn"], counts["ok"]),
           "<h2>Итог</h2><ul class='verdict'>"]
    out += ["<li>%s</li>" % _esc(v) for v in data.get("verdict", [])]
    out.append("</ul></div>")
    if events is not None:
        bad_ev = [e for e in events if e.get("level") in ("warn", "fail")]
        out.append("<div class='box'><h2 style='margin-top:0'>Мониторинг: что пропадало</h2>")
        if monitor_summary:
            out.append("<div class='meta'>%s</div>" % _esc(monitor_summary))
        if bad_ev:
            out.append("<table class='ev'>")
            for e in bad_ev[-200:]:
                label, fg, bg = STATUS_RU.get(e["level"], STATUS_RU["info"])
                out.append("<tr><td class='n'>%s</td><td class='c1'><span class='st' style='color:%s;"
                           "background:%s'>%s</span></td><td>%s</td></tr>" % (
                               _esc(e["time"].replace("T", " ")), fg, bg, label,
                               _esc(e["text"]).replace("\n", "<br>")))
            out.append("</table>")
        else:
            out.append("<p>За время мониторинга обрывов не было.</p>")
        out.append("</div>")
    group = None
    for c in checks:
        if c["group"] != group:
            if group is not None:
                out.append("</table></div>")
            group = c["group"]
            out.append("<div class='box'><h2 style='margin-top:0'>%s</h2><table>" % _esc(group))
        label, fg, bg = STATUS_RU.get(c["status"], STATUS_RU["info"])
        out.append("<tr><td class='c1'><span class='st' style='color:%s;background:%s'>%s</span></td>"
                   "<td class='n'>%s</td><td>%s</td></tr>" % (
                       fg, bg, label, _esc(c["name"]), _esc(c["summary"])))
    if group is not None:
        out.append("</table></div>")
    out.append("<div class='box'><h2 style='margin-top:0'>Сетевые адаптеры</h2><table>")
    for a in data.get("adapters", []):
        if a.get("loopback"):
            continue
        out.append("<tr><td><b>%s</b><br><span class='meta'>%s</span></td><td>%s</td>"
                   "<td class='meta'>шлюз %s<br>DNS %s</td></tr>" % (
                       _esc(a["name"]), _esc(a["description"]),
                       _esc(", ".join(a["ipv4"]) or a["status"]),
                       _esc(", ".join(a["gateway"]) or "-"), _esc(", ".join(a["dns"]) or "-")))
    out.append("</table></div><p class='meta'>Этот файл входит в zip-отчёт. Для разбора "
               "проблемы отправьте zip-файл целиком.</p></main></body></html>")
    return "\n".join(out)


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


def _add_continent(z):
    """Настройки и журналы клиента Континента - находятся сами, без раздела [logs]."""
    notes = []
    try:
        for f in continent.config_files():
            try:  # копия без паролей и прочих секретных полей, не сам файл
                z.writestr("continent/" + os.path.basename(f), json.dumps(
                    continent.load_json_safe(f), ensure_ascii=False, indent=2))
            except (OSError, ValueError) as e:
                notes.append("Континент: %s - %s" % (f, e))
        total = 0
        for f in continent.log_files():
            if total >= MAX_CONTINENT_LOGS:
                notes.append("Континент: остальные журналы не вошли (ограничение %d МБ)"
                             % (MAX_CONTINENT_LOGS // 2 ** 20))
                break
            try:
                size = os.path.getsize(f)
                total += min(size, MAX_LOG_FILE)
                with open(f, "rb") as fh:
                    if size > MAX_LOG_FILE:
                        fh.seek(size - MAX_LOG_FILE)
                    rel = os.path.basename(os.path.dirname(f)) + "/" + os.path.basename(f)
                    z.writestr("continent/logs/" + rel, fh.read())
            except OSError as e:
                notes.append("Континент: %s - %s" % (f, e))
    except Exception as e:
        notes.append("Континент: журналы не собраны (%s)" % e)
    return notes


def build_zip(data, cfg, path=None, folder=None, events=None, monitor_summary=None):
    """Собирает отчёт в zip: проверка, журналы, системные выводы, логи VPN.

    folder - папка отчётов: туда кладётся zip и рядом «Отчёт ....html» для чтения,
    а из неё берутся журналы мониторинга за последние 3 дня.
    Возвращает путь к zip.
    """
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    human = datetime.datetime.now().strftime("%Y-%m-%d %H-%M")
    host = "".join(ch for ch in socket.gethostname() if ch.isalnum() or ch in "-_") or "pc"
    if not path and folder:
        path = os.path.join(folder, "Отчёт %s %s.zip" % (host, human))
    path = path or os.path.join(reports_dir(), "ipinfo-%s-%s.zip" % (host, stamp))
    page = format_html(data, events, monitor_summary)
    if folder:
        try:
            with open(path[:-4] + ".html", "w", encoding="utf-8") as f:
                f.write(page)
        except OSError as e:
            log.warning("не удалось сохранить html-отчёт: %s", e)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("Отчёт.html", page)
        z.writestr("report.txt", format_text(data))
        z.writestr("report.json", json.dumps(data, ensure_ascii=False, indent=2, default=str))
        for name, text in winsys.system_dumps().items():
            z.writestr("system/" + name, text)
        rdp_events = winsys.rdp_client_events(3 * 24 * 60)
        if rdp_events is not None:
            z.writestr("system/rdp_client_events.json",
                       json.dumps(rdp_events, ensure_ascii=False, indent=2))
        if cfg.get("path") and os.path.exists(cfg["path"]):
            z.write(cfg["path"], "ipinfo.ini")
        for f in sorted(glob.glob(os.path.join(logs_dir(), "*"))):
            if os.path.isfile(f):
                z.write(f, "ipinfo_logs/" + os.path.basename(f))
        if folder:
            import time as _time
            for f in glob.glob(os.path.join(folder, "Мониторинг *.txt")):
                if _time.time() - os.path.getmtime(f) < 3 * 86400:
                    z.write(f, "мониторинг/" + os.path.basename(f))
        notes = _add_vpn_logs(z, cfg.get("logs", {}))
        notes += _add_continent(z)
        info = ["IPInfo %s" % __version__, "Собран: %s" % stamp,
                "Компьютер: %s" % socket.gethostname(), "ОС: %s" % platform.platform(),
                "Пользователь: %s" % (os.environ.get("USERNAME") or os.environ.get("USER", ""))]
        if not cfg.get("logs"):
            notes.append("пути к журналам VPN-клиентов не заданы (раздел [logs] в ipinfo.ini)")
        z.writestr("about.txt", "\n".join(info + [""] + notes) + "\n")
    log.info("отчёт сохранён: %s", path)
    return path
