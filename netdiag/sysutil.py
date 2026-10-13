# -*- coding: utf-8 -*-
"""Общие системные функции: пути, запуск команд, PowerShell."""

import json
import os
import platform
import subprocess
import sys

IS_WINDOWS = platform.system() == "Windows"
FROZEN = getattr(sys, "frozen", False)

# Без этого флага каждый вызов ping/netsh из оконного exe мигает консолью.
CREATE_NO_WINDOW = 0x08000000


def resource_path(name):
    """Путь к ресурсу рядом со скриптом или внутри собранного exe."""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(base, name)


def app_dir():
    """Папка, где лежит exe (или ipinfo.py при запуске из исходников)."""
    if FROZEN:
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def data_dir():
    """Папка для журналов и отчётов: %LOCALAPPDATA%\\IPInfo или ~/.ipinfo."""
    if IS_WINDOWS:
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        path = os.path.join(base, "IPInfo")
    else:
        path = os.path.join(os.path.expanduser("~"), ".ipinfo")
    os.makedirs(path, exist_ok=True)
    return path


def _decode(raw):
    if not raw:
        return ""
    for enc in ("utf-8", "cp866", "cp1251"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")


def run(cmd, timeout=15):
    """Запускает команду, возвращает её вывод (stdout + stderr) строкой.

    Вывод консольных утилит Windows идёт в OEM-кодировке (cp866 на русской
    системе), поэтому декодируем сами, а не через text=True.
    """
    kw = {}
    if IS_WINDOWS:
        kw["creationflags"] = CREATE_NO_WINDOW
    try:
        p = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=timeout, **kw)
        return _decode(p.stdout)
    except subprocess.TimeoutExpired:
        return "(команда не завершилась за %d с)" % timeout
    except Exception as e:
        return "(не удалось запустить: %s)" % e


def powershell_json(script, timeout=30):
    """Выполняет скрипт PowerShell, который печатает JSON, и разбирает ответ.

    Возвращает объект или None, если PowerShell недоступен или ответ не JSON.
    """
    if not IS_WINDOWS:
        return None
    full = "[Console]::OutputEncoding = [Text.Encoding]::UTF8; " \
           "$ErrorActionPreference = 'SilentlyContinue'; " + script
    out = run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
               "-Command", full], timeout=timeout)
    start = min([i for i in (out.find("{"), out.find("[")) if i >= 0] or [-1])
    if start < 0:
        return None
    try:
        return json.loads(out[start:])
    except ValueError:
        return None


def attach_console():
    """В оконном exe нет консоли, и print() молча ничего не выводит.

    Подключаемся к консоли, из которой запущен exe (cmd / PowerShell),
    чтобы работали --cli, --json и --check.
    """
    if not (IS_WINDOWS and FROZEN) or sys.stdout is not None:
        return
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        if k32.AttachConsole(-1):  # ATTACH_PARENT_PROCESS
            enc = "cp%d" % (k32.GetConsoleOutputCP() or 866)
            sys.stdout = open("CONOUT$", "w", encoding=enc, errors="replace")
            sys.stderr = sys.stdout
    except Exception:
        pass
