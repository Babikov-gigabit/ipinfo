#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ipinfo - сетевые адаптеры и диагностика VPN (Континент, OpenConnect).

Только стандартная библиотека Python (ctypes / tkinter / urllib).

Запуск:
    python ipinfo.py              # окно
    python ipinfo.py --cli        # адаптеры в консоль
    python ipinfo.py --check      # полная проверка сети и VPN в консоль
    python ipinfo.py --report     # проверка + zip-отчёт для отправки
    python ipinfo.py --all        # включая выключенные адаптеры и loopback
    python ipinfo.py --no-net     # не запрашивать внешний IP
    python ipinfo.py --json       # вывод в JSON (адаптеры, с --check - вся проверка)
    python ipinfo.py --config F   # другой файл настроек вместо ipinfo.ini
"""

import argparse
import json
import queue
import sys
import threading
import traceback

from netdiag import __version__, adapters as ad, config, diagnose, monitor, probes, report
from netdiag.sysutil import attach_console, resource_path

ICON_NAME = "ip-icon.ico"
log = report.log


def get_adapters(include_down=False):
    """Адаптеры для окна и --cli.

    Без --all показываются активные адаптеры с IP, а также отключённые
    Ethernet и Wi-Fi: «кабель не подключён» - тоже важная информация.
    """
    data = ad.get_adapters(include_down=True)
    if include_down:
        return data
    return [a for a in data if not a.get("loopback") and (
        (a["up"] and (a["ipv4"] or a["ipv6"])) or (not a["up"] and a.get("iftype") in (6, 71)))]


def get_external_ip():
    ip, _err = probes.external_ip()
    return ip or "нет связи"


# --------------------------------------------------------------------------
# Консоль
# --------------------------------------------------------------------------
def print_console(adapters, external=None):
    if not adapters:
        print("Активных адаптеров с IP не найдено (попробуйте --all).")
        return
    line = "-" * 66
    print()
    print("  СЕТЕВЫЕ АДАПТЕРЫ")
    print("  " + line)
    for a in adapters:
        print()
        print("  %s  [%s]  %s" % (a["name"], a["status"], a["type"]))
        if a["description"] and a["description"] != a["name"]:
            print("    %s" % a["description"])
        print("    IPv4    : %s" % (", ".join(a["ipv4"]) or "-"))
        if any(ad.is_apipa(ip) for ip in ad.ipv4_addrs(a)):
            print("    !!      : адрес 169.254.x.x - DHCP не выдал адрес")
        if a["ipv6"]:
            print("    IPv6    : %s" % ", ".join(a["ipv6"]))
        print("    Шлюз    : %s" % (", ".join(a["gateway"]) or "-"))
        print("    DNS     : %s" % (", ".join(a["dns"]) or "-"))
        print("    MAC     : %-20s MTU: %s  Скорость: %s" % (a["mac"], a["mtu"], a["speed"]))
    if external:
        print()
        print("  " + line)
        print("  Внешний IP: %s" % external)
    print()


def console_check(args, cfg):
    def progress(c):
        if not args.json:
            print("  " + report.format_check(c), flush=True)

    if not args.json:
        print("Проверка сети... (настройки: %s)" % (cfg["path"] or "по умолчанию"), flush=True)
    data = diagnose.run(cfg, progress=progress)
    report.save_check(data)
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2, default=str))
    else:
        print()
        print("ИТОГ")
        for v in data["verdict"]:
            print("  * " + v)
    if args.report:
        path = report.build_zip(data, cfg)
        print("\nОтчёт сохранён: %s" % path)


# --------------------------------------------------------------------------
# GUI - минималистичный список карточек
# --------------------------------------------------------------------------
BG = "#ffffff"          # фон
BG_HOVER = "#f4f4f5"    # подсветка карточки под курсором
FG = "#18181b"          # основной текст
FG_MUTED = "#a1a1aa"    # подписи
RULE = "#ececee"        # разделители
DOT_UP = "#22c55e"      # индикатор активного адаптера
DOT_DOWN = "#d4d4d8"
FG_WARN = "#d97706"
FG_FAIL = "#dc2626"
FG_OK = "#16a34a"
STATUS_COLOR = {"ok": FG_OK, "warn": FG_WARN, "fail": FG_FAIL, "info": FG_MUTED}


def run_gui(include_down, want_external, cfg_path=None):
    import tkinter as tk
    from tkinter import font as tkfont, messagebox

    root = tk.Tk()
    root.title("IP")
    root.configure(bg=BG)
    root.geometry("400x520")
    root.minsize(340, 300)
    try:
        root.iconbitmap(resource_path(ICON_NAME))
    except Exception:
        pass

    def on_error(exc, val, tb):
        log.error("ошибка в окне: %s", "".join(traceback.format_exception(exc, val, tb)))
        messagebox.showerror("IPInfo", "Ошибка: %s\n\nПодробности в журнале:\n%s"
                             % (val, report.logs_dir()))

    root.report_callback_exception = on_error

    family = "Segoe UI" if "Segoe UI" in tkfont.families() else "Helvetica"
    f_label = (family, 8)
    f_ip = (family, 19)
    f_meta = (family, 8)
    f_head = (family, 9)

    # Фоновые потоки не трогают tkinter: они кладут функции в очередь,
    # а главный поток выполняет их по таймеру.
    ui_queue = queue.Queue()

    def pump():
        try:
            while True:
                ui_queue.get_nowait()()
        except queue.Empty:
            pass
        root.after(100, pump)

    def in_background(work, done):
        def runner():
            try:
                res = work()
            except Exception as e:
                log.exception("ошибка в фоновой задаче")
                res = e
            ui_queue.put(lambda: done(res))
        threading.Thread(target=runner, daemon=True).start()

    state = {"toast": None, "gen": 0}

    # --- шапка ---------------------------------------------------------
    head = tk.Frame(root, bg=BG)
    head.pack(fill="x", padx=22, pady=(18, 6))

    tk.Label(head, text="СЕТЬ", font=(family, 8, "bold"), fg=FG_MUTED, bg=BG).pack(side="left")

    def head_button(text, size=8):
        b = tk.Label(head, text=text, font=(family, size), fg=FG_MUTED, bg=BG, cursor="hand2")
        b.pack(side="right", padx=(10, 0))
        b.bind("<Enter>", lambda _e: b.config(fg=FG))
        b.bind("<Leave>", lambda _e: b.config(fg=FG_MUTED))
        return b

    reload_btn = head_button("↻", 13)
    check_btn = head_button("ПРОВЕРКА")
    monitor_btn = head_button("МОНИТОРИНГ")

    # --- прокручиваемая область ----------------------------------------
    canvas = tk.Canvas(root, bg=BG, highlightthickness=0, bd=0)
    body = tk.Frame(canvas, bg=BG)
    win = canvas.create_window((0, 0), window=body, anchor="nw")

    def on_body_configure(_e=None):
        canvas.configure(scrollregion=canvas.bbox("all"))

    def on_canvas_configure(e):
        canvas.itemconfig(win, width=e.width)

    body.bind("<Configure>", on_body_configure)
    canvas.bind("<Configure>", on_canvas_configure)

    def on_wheel(e):
        canvas.yview_scroll(-1 * (e.delta // 120), "units")

    canvas.bind("<MouseWheel>", on_wheel)
    body.bind("<MouseWheel>", on_wheel)

    # --- подвал --------------------------------------------------------
    foot = tk.Frame(root, bg=BG)
    foot.pack(fill="x", side="bottom")
    canvas.pack(fill="both", expand=True)
    tk.Frame(foot, bg=RULE, height=1).pack(fill="x")
    foot_row = tk.Frame(foot, bg=BG)
    foot_row.pack(fill="x", padx=22, pady=12)
    ext_label = tk.Label(foot_row, text="внешний  —", font=f_meta, fg=FG_MUTED, bg=BG)
    ext_label.pack(side="left")
    hint = tk.Label(foot_row, text="клик — копировать", font=f_meta, fg=FG_MUTED, bg=BG)
    hint.pack(side="right")

    def toast(text):
        if state["toast"]:
            root.after_cancel(state["toast"])
        hint.config(text=text, fg=FG)
        state["toast"] = root.after(1400, lambda: hint.config(text="клик — копировать", fg=FG_MUTED))

    # --- карточка адаптера ---------------------------------------------
    cfg_for_cards = config.load(cfg_path)

    def add_card(a, first):
        if not first:
            tk.Frame(body, bg=RULE, height=1).pack(fill="x", padx=22)

        card = tk.Frame(body, bg=BG, cursor="hand2")
        card.pack(fill="x")
        inner = tk.Frame(card, bg=BG)
        inner.pack(fill="x", padx=22, pady=13)

        top = tk.Frame(inner, bg=BG)
        top.pack(fill="x")
        title = a["name"].upper()
        tunnels, _l, _i, _c = diagnose.classify([a], cfg_for_cards)
        if tunnels:
            title += "  ·  VPN " + tunnels[0]["client"].upper()
        tk.Label(top, text=title, font=f_label, fg=FG_MUTED, bg=BG,
                 anchor="w").pack(side="left")
        tk.Label(top, text="●", font=(family, 7), bg=BG,
                 fg=DOT_UP if a["up"] else DOT_DOWN).pack(side="right")

        ip = a["ipv4"][0].split("/")[0] if a["ipv4"] else (
            a["ipv6"][0].split("/")[0] if a["ipv6"] else "—")
        if not a["up"]:
            ip_text, ip_fg = "не подключён", FG_MUTED
        elif ad.is_apipa(ip):
            ip_text, ip_fg = ip, FG_FAIL
        else:
            ip_text, ip_fg = ip, FG
        tk.Label(inner, text=ip_text, font=f_ip, fg=ip_fg, bg=BG, anchor="w").pack(
            fill="x", pady=(1, 2))

        bits = []
        if a["ipv4"] and "/" in a["ipv4"][0]:
            bits.append(ad.prefix_to_mask(a["ipv4"][0].split("/")[1]))
        if a["gateway"]:
            bits.append("шлюз " + a["gateway"][0])
        if ad.is_apipa(ip):
            bits = ["DHCP не выдал адрес"]
        if bits:
            tk.Label(inner, text="   ·   ".join(bits), font=f_meta, fg=FG_MUTED, bg=BG,
                     anchor="w").pack(fill="x")
        meta = []
        if a["dns"]:
            meta.append("DNS " + ", ".join(a["dns"][:2]))
        if a["up"]:
            meta.append("MTU %s" % a["mtu"])
            if a["speed"] != "-":
                meta.append(a["speed"])
        if meta:
            tk.Label(inner, text="   ·   ".join(meta), font=f_meta, fg=FG_MUTED, bg=BG,
                     anchor="w").pack(fill="x")

        widgets = (card, inner, top) + tuple(inner.winfo_children()) + tuple(top.winfo_children())

        def paint(color):
            for w in widgets:
                try:
                    w.configure(bg=color)
                except tk.TclError:
                    pass

        def copy(_e=None):
            if ip == "—" or not a["up"]:
                return
            root.clipboard_clear()
            root.clipboard_append(ip)
            toast("скопировано  " + ip)

        for w in widgets:
            w.bind("<Button-1>", copy)
            w.bind("<Enter>", lambda _e: paint(BG_HOVER))
            w.bind("<Leave>", lambda _e: paint(BG))
            w.bind("<MouseWheel>", on_wheel)

    # --- обновление ----------------------------------------------------
    def refresh(_e=None):
        state["gen"] += 1
        gen = state["gen"]
        for w in body.winfo_children():
            w.destroy()
        try:
            adapters = get_adapters(include_down=include_down)
        except Exception as e:
            log.exception("не удалось получить список адаптеров")
            adapters = []
            tk.Label(body, text="ошибка: %s" % e, font=f_head, fg=FG_FAIL, bg=BG,
                     wraplength=320).pack(pady=40)
        if not adapters:
            tk.Label(body, text="адаптеров с IP нет", font=f_head, fg=FG_MUTED,
                     bg=BG).pack(pady=40)
        for i, a in enumerate(adapters):
            add_card(a, first=(i == 0))
        on_body_configure()

        if want_external:
            ext_label.config(text="внешний  …")

            def show(ip):
                if gen == state["gen"]:  # не перезаписывать более свежий ответ
                    ext_label.config(text="внешний  " + (ip if isinstance(ip, str) else "?"))

            in_background(get_external_ip, show)
        else:
            ext_label.config(text="")

    # --- окно проверки -------------------------------------------------
    def open_check(_e=None):
        if state.get("check_win") and state["check_win"].winfo_exists():
            state["check_win"].lift()
            return
        cfg_file = cfg_path or config.ensure_config()
        cfg = config.load(cfg_file)

        w = tk.Toplevel(root)
        state["check_win"] = w
        w.title("Проверка сети")
        w.configure(bg=BG)
        w.geometry("640x560")
        try:
            w.iconbitmap(resource_path(ICON_NAME))
        except Exception:
            pass

        bar = tk.Frame(w, bg=BG)
        bar.pack(fill="x", padx=16, pady=(12, 6))
        status = tk.Label(bar, text="проверка…", font=f_head, fg=FG_MUTED, bg=BG)
        status.pack(side="left")

        def link(text, cmd):
            b = tk.Label(bar, text=text, font=f_meta, fg=FG_MUTED, bg=BG, cursor="hand2")
            b.pack(side="right", padx=(12, 0))
            b.bind("<Button-1>", cmd)
            b.bind("<Enter>", lambda _e: b.config(fg=FG))
            b.bind("<Leave>", lambda _e: b.config(fg=FG_MUTED))
            return b

        txt = tk.Text(w, font=(family, 9), bg=BG, fg=FG, relief="flat", wrap="word",
                      padx=16, pady=8, highlightthickness=0)
        sb = tk.Scrollbar(w, command=txt.yview)
        txt.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        txt.pack(fill="both", expand=True)
        for k, color in STATUS_COLOR.items():
            txt.tag_configure(k, foreground=color)
        txt.tag_configure("group", font=(family, 8, "bold"), foreground=FG_MUTED,
                          spacing1=10)
        txt.tag_configure("verdict", font=(family, 10, "bold"), spacing1=4)
        txt.tag_configure("muted", foreground=FG_MUTED)

        run_state = {"group": None, "data": None, "busy": False}

        def put(text, *tags):
            txt.configure(state="normal")
            txt.insert("end", text, tags)
            txt.see("end")
            txt.configure(state="disabled")

        def on_progress(c):
            def show():
                if c["group"] != run_state["group"]:
                    run_state["group"] = c["group"]
                    put(c["group"].upper() + "\n", "group")
                put("  ● ", c["status"])
                put("%s: " % c["name"])
                put(c["summary"] + "\n", *(("muted",) if c["status"] == "info" else ()))
            ui_queue.put(show)

        def finished(data):
            run_state["busy"] = False
            if isinstance(data, Exception):
                status.config(text="ошибка проверки", fg=FG_FAIL)
                put("\nОшибка: %s\nПодробности в журнале: %s\n" % (data, report.logs_dir()),
                    "fail")
                return
            run_state["data"] = data
            report.save_check(data)
            bad = any(c["status"] == "fail" for c in data["checks"])
            status.config(text="есть проблемы" if bad else "проблем не найдено",
                          fg=FG_FAIL if bad else FG_OK)
            put("\nИТОГ\n", "group")
            for v in data["verdict"]:
                put(v + "\n", "verdict")
            put("\nПроверка заняла %s с. Настройки: %s\n" % (
                data["duration_sec"], cfg["path"] or "по умолчанию"), "muted")

        def start(_e=None):
            if run_state["busy"]:
                return
            run_state.update(busy=True, group=None, data=None)
            txt.configure(state="normal")
            txt.delete("1.0", "end")
            txt.configure(state="disabled")
            status.config(text="проверка…", fg=FG_MUTED)
            in_background(lambda: diagnose.run(cfg, progress=on_progress), finished)

        def save_report(_e=None):
            if run_state["busy"]:
                toast("дождитесь окончания проверки")
                return
            if not run_state["data"]:
                return
            status.config(text="собираю отчёт…", fg=FG_MUTED)

            def done(path):
                if isinstance(path, Exception):
                    status.config(text="отчёт не собран: %s" % path, fg=FG_FAIL)
                    return
                status.config(text="отчёт сохранён", fg=FG_OK)
                put("\nОтчёт: %s\n" % path, "verdict")
                _show_in_explorer(path)

            in_background(lambda: report.build_zip(run_state["data"], cfg), done)

        def open_config(_e=None):
            _open_file(cfg_file)

        def continent_collector(_e=None):
            from netdiag import continent
            path = continent.collector_path()
            if path:
                _open_file(path)
            else:
                toast("утилита диагностики Континента не найдена")

        link("настройки", open_config)
        link("диагностика Континента", continent_collector)
        link("сохранить отчёт", save_report)
        link("повторить", start)
        w.bind("<Escape>", lambda _e: w.destroy())
        start()

    # --- окно мониторинга --------------------------------------------
    def open_monitor(_e=None):
        if state.get("mon_win") and state["mon_win"].winfo_exists():
            state["mon_win"].deiconify()
            state["mon_win"].lift()
            return
        cfg_file = cfg_path or config.ensure_config()
        cfg = config.load(cfg_file)

        w = tk.Toplevel(root)
        state["mon_win"] = w
        w.title("Мониторинг связи")
        w.configure(bg=BG)
        w.geometry("720x480")
        try:
            w.iconbitmap(resource_path(ICON_NAME))
        except Exception:
            pass

        bar = tk.Frame(w, bg=BG)
        bar.pack(fill="x", padx=16, pady=(12, 6))
        status = tk.Label(bar, text="", font=f_head, fg=FG_MUTED, bg=BG)
        status.pack(side="left")
        txt = tk.Text(w, font=("Consolas", 9), bg=BG, fg=FG, relief="flat", wrap="word",
                      padx=16, pady=8, highlightthickness=0, state="disabled")
        sb = tk.Scrollbar(w, command=txt.yview)
        txt.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        txt.pack(fill="both", expand=True)
        for k, color in STATUS_COLOR.items():
            txt.tag_configure(k, foreground=color)

        mon_state = {"mon": None, "fails": 0}

        def put(line, level):
            txt.configure(state="normal")
            txt.insert("end", line + "\n", (level,))
            txt.see("end")
            txt.configure(state="disabled")

        def on_event(ev, line):
            def show():
                put(line, ev["level"])
                if ev["level"] == "fail":
                    mon_state["fails"] += 1
                if mon_state["mon"] and not mon_state["mon"].stop_event.is_set():
                    status.config(text="идёт мониторинг · событий с ошибками: %d"
                                  % mon_state["fails"], fg=FG_FAIL if mon_state["fails"] else FG_OK)
            ui_queue.put(show)

        def start(_e=None):
            if mon_state["mon"] and not mon_state["mon"].stop_event.is_set():
                return
            mon_state["fails"] = 0
            m = monitor.Monitor(cfg, interval=2, on_event=on_event)
            mon_state["mon"] = m
            put("журнал: %s" % m.text_path, "info")
            status.config(text="идёт мониторинг", fg=FG_OK)
            m.start()

        def stop(_e=None):
            if mon_state["mon"]:
                mon_state["mon"].stop()
                status.config(text="остановлен", fg=FG_MUTED)

        def save_report(_e=None):
            status.config(text="собираю отчёт…", fg=FG_MUTED)

            def work():
                data = diagnose.run(cfg)
                report.save_check(data)
                return report.build_zip(data, cfg)

            def done(path):
                if isinstance(path, Exception):
                    status.config(text="отчёт не собран: %s" % path, fg=FG_FAIL)
                    return
                status.config(text="отчёт сохранён", fg=FG_OK)
                put("отчёт: %s" % path, "info")
                _show_in_explorer(path)

            in_background(work, done)

        def on_close():
            if mon_state["mon"] and not mon_state["mon"].stop_event.is_set():
                if not messagebox.askyesno("IPInfo", "Остановить мониторинг?\n\n"
                                           "Чтобы он продолжал работать, сверните окно."):
                    return
                stop()
            w.destroy()

        for text, cmd in (("отчёт", save_report), ("стоп", stop), ("старт", start)):
            b = tk.Label(bar, text=text, font=f_meta, fg=FG_MUTED, bg=BG, cursor="hand2")
            b.pack(side="right", padx=(12, 0))
            b.bind("<Button-1>", cmd)
            b.bind("<Enter>", lambda _e, b=b: b.config(fg=FG))
            b.bind("<Leave>", lambda _e, b=b: b.config(fg=FG_MUTED))
        w.protocol("WM_DELETE_WINDOW", on_close)
        start()

    reload_btn.bind("<Button-1>", refresh)
    check_btn.bind("<Button-1>", open_check)
    monitor_btn.bind("<Button-1>", open_monitor)
    root.bind("<F5>", refresh)
    root.bind("<Escape>", lambda _e: root.destroy())

    pump()
    refresh()
    root.mainloop()


def _show_in_explorer(path):
    import os
    import subprocess
    try:
        if os.name == "nt":
            subprocess.Popen(["explorer", "/select,", path])
    except Exception:
        pass


def _open_file(path):
    import os
    try:
        if os.name == "nt":
            os.startfile(path)  # откроется в Блокноте или редакторе по умолчанию
    except Exception as e:
        log.warning("не удалось открыть %s: %s", path, e)


def main():
    p = argparse.ArgumentParser(description="IPInfo %s: сетевые адаптеры и диагностика VPN"
                                % __version__)
    p.add_argument("--cli", action="store_true", help="консольный вывод вместо окна")
    p.add_argument("--check", action="store_true", help="полная проверка сети и VPN")
    p.add_argument("--report", action="store_true", help="проверка и zip-отчёт для отправки")
    p.add_argument("--monitor", action="store_true",
                   help="фоновый мониторинг обрывов до Ctrl+C (журнал в logs)")
    p.add_argument("--interval", type=float, default=2.0, metavar="СЕК",
                   help="интервал мониторинга, по умолчанию 2 с")
    p.add_argument("--all", action="store_true", help="включая выключенные адаптеры")
    p.add_argument("--no-net", action="store_true", help="не запрашивать внешний IP")
    p.add_argument("--json", action="store_true", help="вывод в формате JSON")
    p.add_argument("--config", metavar="FILE", help="файл настроек вместо ipinfo.ini")
    p.add_argument("--version", action="version", version="IPInfo %s" % __version__)
    args = p.parse_args()

    log.info("запуск IPInfo %s, ключи: %s", __version__, " ".join(sys.argv[1:]) or "-")

    if args.monitor:
        cfg = config.load(args.config or config.ensure_config())
        m = monitor.Monitor(cfg, interval=args.interval,
                            on_event=lambda ev, line: print(line, flush=True))
        print("Журнал: %s\nОстановить: Ctrl+C\n" % m.text_path, flush=True)
        m.start()
        try:
            while m.thread.is_alive():
                m.thread.join(0.5)
        except KeyboardInterrupt:
            m.stop()
            m.thread.join(30)
        return

    if args.check or args.report:
        cfg = config.load(args.config or config.ensure_config())
        console_check(args, cfg)
        return

    if args.json:
        data = {"adapters": get_adapters(include_down=args.all)}
        if not args.no_net:
            data["external_ip"] = get_external_ip()
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return

    if not args.cli:
        try:
            run_gui(include_down=args.all, want_external=not args.no_net, cfg_path=args.config)
            return
        except Exception as e:
            log.exception("окно не запустилось")
            print("GUI недоступен (%s), вывожу в консоль.\n" % e)

    print_console(get_adapters(include_down=args.all),
                  external=None if args.no_net else get_external_ip())


def _fatal(exc):
    """Последний рубеж: записать ошибку в журнал и показать её, а не молча закрыться."""
    log.error("необработанная ошибка: %s", "".join(traceback.format_exception(
        type(exc), exc, exc.__traceback__)))
    msg = "IPInfo: %s\n\nПодробности в журнале:\n%s" % (exc, report.logs_dir())
    if sys.stdout is not None:
        print(msg, file=sys.stderr if sys.stderr else sys.stdout)
        return
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(None, msg, "IPInfo", 0x10)
    except Exception:
        pass


if __name__ == "__main__":
    if len(sys.argv) > 1:
        attach_console()
    report.setup_logging()
    try:
        main()
    except KeyboardInterrupt:
        pass
    except SystemExit:
        raise
    except Exception as e:
        _fatal(e)
        sys.exit(1)
