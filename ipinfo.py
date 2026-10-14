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
import os
import queue
import sys
import threading
import traceback

from netdiag import __version__, adapters as ad, config, diagnose, monitor, probes, report
from netdiag.sysutil import attach_console, reports_folder, resource_path

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
ACCENT = "#2563eb"      # кнопка «Собрать отчёт»
ACCENT_HOVER = "#1d4ed8"
PANEL_W = 620           # ширина выезжающей справа панели


def run_gui(include_down, want_external, cfg_path=None):
    import tkinter as tk
    from tkinter import font as tkfont, messagebox

    root = tk.Tk()
    root.title("IP")
    root.configure(bg=BG)
    root.geometry("400x560")
    root.minsize(340, 300)
    cfg_file = cfg_path or config.ensure_config()
    cfg = config.load(cfg_file)
    folder = reports_folder(cfg.get("report_folder"))
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

    # Слева - адаптеры, справа - выезжающая панель проверки и мониторинга
    left = tk.Frame(root, bg=BG)
    left.pack(side="left", fill="both", expand=True)

    # --- шапка ---------------------------------------------------------
    head = tk.Frame(left, bg=BG)
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
    canvas = tk.Canvas(left, bg=BG, highlightthickness=0, bd=0)
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
    foot = tk.Frame(left, bg=BG)
    foot.pack(fill="x", side="bottom")
    canvas.pack(fill="both", expand=True)
    tk.Frame(foot, bg=RULE, height=1).pack(fill="x")
    report_btn = tk.Label(foot, text="СОБРАТЬ ОТЧЁТ", font=(family, 10, "bold"), fg="#ffffff",
                          bg=ACCENT, cursor="hand2", pady=9)
    report_btn.pack(fill="x", padx=22, pady=(12, 0))
    report_btn.bind("<Enter>", lambda _e: report_btn.config(bg=ACCENT_HOVER))
    report_btn.bind("<Leave>", lambda _e: report_btn.config(bg=ACCENT))
    folder_link = tk.Label(foot, text="папка отчётов", font=f_meta, fg=FG_MUTED, bg=BG,
                           cursor="hand2")
    folder_link.pack(pady=(4, 0))
    folder_link.bind("<Button-1>", lambda _e: _open_file(folder))
    folder_link.bind("<Enter>", lambda _e: folder_link.config(fg=FG))
    folder_link.bind("<Leave>", lambda _e: folder_link.config(fg=FG_MUTED))
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
    cfg_for_cards = cfg

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

    # --- выезжающая панель справа ---------------------------------------
    side = tk.Frame(root, bg=BG, highlightthickness=1, highlightbackground=RULE)
    tabs = tk.Frame(side, bg=BG)
    tabs.pack(fill="x", padx=16, pady=(14, 4))
    pages = {}
    tab_labels = {}
    panel = {"open": False, "tab": None, "anim": None}

    def show_tab(name):
        panel["tab"] = name
        for n, frame in pages.items():
            frame.pack_forget()
            tab_labels[n].config(fg=FG if n == name else FG_MUTED,
                                 font=(family, 9, "bold" if n == name else "normal"))
        pages[name].pack(fill="both", expand=True)

    def animate(target_w, done=None, last=None):
        """Плавно меняет ширину окна, не уводя его за край экрана."""
        if panel["anim"]:
            root.after_cancel(panel["anim"])
        root.update_idletasks()
        w, h = root.winfo_width(), root.winfo_height()
        if w == last:  # окно не поддаётся (развёрнуто, упёрлось в minsize) - сразу в цель
            w = target_w
        x, y = root.winfo_x(), root.winfo_y()
        step = max(1, abs(target_w - w) // 4)
        new_w = target_w if abs(target_w - w) <= step else w + (step if target_w > w else -step)
        screen = root.winfo_screenwidth()
        if x + new_w > screen:
            x = max(0, screen - new_w)
        root.geometry("%dx%d+%d+%d" % (new_w, h, x, y))
        if new_w != target_w:
            panel["anim"] = root.after(12, lambda: animate(target_w, done, new_w))
        else:
            panel["anim"] = None
            if done:
                done()

    def open_panel(name):
        show_tab(name)
        if panel["open"]:
            return
        panel["open"] = True
        root.update_idletasks()
        left_w = root.winfo_width()
        left.pack_forget()
        left.configure(width=left_w)
        left.pack_propagate(False)
        left.pack(side="left", fill="y")
        side.pack(side="left", fill="both", expand=True)
        root.minsize(340 + 420, 300)
        animate(left_w + PANEL_W)

    def close_panel(_e=None):
        if not panel["open"]:
            return
        panel["open"] = False
        target = left.winfo_width()
        root.minsize(340, 300)

        def finish():
            side.pack_forget()
            left.pack_forget()
            left.pack_propagate(True)
            left.pack(side="left", fill="both", expand=True)
        animate(target, finish)

    def tab_button(name, text):
        b = tk.Label(tabs, text=text, font=(family, 9), fg=FG_MUTED, bg=BG, cursor="hand2")
        b.pack(side="left", padx=(0, 16))
        b.bind("<Button-1>", lambda _e: show_tab(name))
        tab_labels[name] = b

    tab_button("check", "ПРОВЕРКА")
    tab_button("monitor", "МОНИТОРИНГ")
    hide = tk.Label(tabs, text="скрыть  ›", font=f_meta, fg=FG_MUTED, bg=BG, cursor="hand2")
    hide.pack(side="right")
    hide.bind("<Button-1>", close_panel)
    tk.Frame(side, bg=RULE, height=1).pack(fill="x")
    body_side = tk.Frame(side, bg=BG)
    body_side.pack(fill="both", expand=True)

    def make_page(name, mono=False):
        page = tk.Frame(body_side, bg=BG)
        pages[name] = page
        bar = tk.Frame(page, bg=BG)
        bar.pack(fill="x", padx=16, pady=(10, 6))
        status = tk.Label(bar, text="", font=f_head, fg=FG_MUTED, bg=BG, anchor="w")
        status.pack(side="left")
        txt = tk.Text(page, font=("Consolas", 9) if mono else (family, 9), bg=BG, fg=FG,
                      relief="flat", wrap="word", padx=16, pady=8, highlightthickness=0,
                      state="disabled")
        sb = tk.Scrollbar(page, command=txt.yview)
        txt.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        txt.pack(fill="both", expand=True)
        for k, color in STATUS_COLOR.items():
            txt.tag_configure(k, foreground=color)
        txt.tag_configure("group", font=(family, 8, "bold"), foreground=FG_MUTED, spacing1=10)
        txt.tag_configure("verdict", font=(family, 10, "bold"), spacing1=4)
        txt.tag_configure("muted", foreground=FG_MUTED)

        def link(text, cmd):
            b = tk.Label(bar, text=text, font=f_meta, fg=FG_MUTED, bg=BG, cursor="hand2")
            b.pack(side="right", padx=(12, 0))
            b.bind("<Button-1>", cmd)
            b.bind("<Enter>", lambda _e: b.config(fg=FG))
            b.bind("<Leave>", lambda _e: b.config(fg=FG_MUTED))
            return b

        def put(text, *tags):
            txt.configure(state="normal")
            txt.insert("end", text, tags)
            txt.see("end")
            txt.configure(state="disabled")

        def clear():
            txt.configure(state="normal")
            txt.delete("1.0", "end")
            txt.configure(state="disabled")
        return status, link, put, clear

    # --- проверка ------------------------------------------------------
    c_status, c_link, c_put, c_clear = make_page("check")
    run_state = {"group": None, "data": None, "busy": False, "after": []}

    def on_progress(c):
        def show():
            if c["group"] != run_state["group"]:
                run_state["group"] = c["group"]
                c_put(c["group"].upper() + "\n", "group")
            c_put("  ● ", c["status"])
            c_put("%s: " % c["name"])
            c_put(c["summary"] + "\n", *(("muted",) if c["status"] == "info" else ()))
        ui_queue.put(show)

    def finished(data):
        run_state["busy"] = False
        callbacks, run_state["after"] = run_state["after"], []
        if isinstance(data, Exception):
            c_status.config(text="ошибка проверки", fg=FG_FAIL)
            c_put("\nОшибка: %s\nПодробности в журнале: %s\n" % (data, report.logs_dir()),
                  "fail")
            for cb in callbacks:
                cb(None)
            return
        run_state["data"] = data
        report.save_check(data)
        try:  # последняя проверка - в папку отчётов, в читаемом виде
            with open(os.path.join(folder, "Последняя проверка.html"), "w",
                      encoding="utf-8") as f:
                f.write(report.format_html(data))
        except OSError as e:
            log.warning("не удалось сохранить проверку в папку отчётов: %s", e)
        bad = any(c["status"] == "fail" for c in data["checks"])
        c_status.config(text="есть проблемы" if bad else "проблем не найдено",
                        fg=FG_FAIL if bad else FG_OK)
        c_put("\nИТОГ\n", "group")
        for v in data["verdict"]:
            c_put(v + "\n", "verdict")
        c_put("\nПроверка заняла %s с. Результат сохранён в папку отчётов.\n"
              % data["duration_sec"], "muted")
        for cb in callbacks:
            cb(data)

    def start_check(_e=None, then=None):
        if then:
            run_state["after"].append(then)
        if run_state["busy"]:
            return
        run_state.update(busy=True, group=None, data=None)
        c_clear()
        c_status.config(text="проверка…", fg=FG_MUTED)
        in_background(lambda: diagnose.run(cfg, progress=on_progress), finished)

    def continent_collector(_e=None):
        from netdiag import continent
        path = continent.collector_path()
        if path:
            _open_file(path)
        else:
            toast("утилита диагностики Континента не найдена")

    c_link("настройки", lambda _e: _open_file(cfg_file))
    c_link("диагностика Континента", continent_collector)
    c_link("повторить", start_check)

    # --- мониторинг ----------------------------------------------------
    m_status, m_link, m_put, _m_clear = make_page("monitor", mono=True)
    mon_state = {"mon": None, "fails": 0}

    def mon_running():
        return mon_state["mon"] is not None and not mon_state["mon"].stop_event.is_set()

    def on_event(ev, line):
        def show():
            m_put(line + "\n", ev["level"])
            if ev["level"] == "fail":
                mon_state["fails"] += 1
            if mon_running():
                m_status.config(text="идёт мониторинг · ошибок: %d" % mon_state["fails"],
                                fg=FG_FAIL if mon_state["fails"] else FG_OK)
                monitor_btn.config(text="МОНИТОРИНГ ●" if not mon_state["fails"]
                                   else "МОНИТОРИНГ ● %d" % mon_state["fails"])
        ui_queue.put(show)

    def start_monitor(_e=None):
        if mon_running():
            return
        mon_state["fails"] = 0
        m = monitor.Monitor(cfg, interval=2, on_event=on_event, out_dir=folder)
        mon_state["mon"] = m
        m_put("журнал пишется в папку отчётов: %s\n" % m.text_path, "info")
        m_status.config(text="идёт мониторинг", fg=FG_OK)
        monitor_btn.config(text="МОНИТОРИНГ ●")
        m.start()

    def stop_monitor(_e=None):
        if mon_state["mon"]:
            mon_state["mon"].stop()
            m_status.config(text="остановлен", fg=FG_MUTED)
            monitor_btn.config(text="МОНИТОРИНГ")

    m_link("стоп", stop_monitor)
    m_link("старт", start_monitor)

    # --- одна кнопка: проверка + отчёт ----------------------------------
    rep_state = {"busy": False}

    def collect_report(_e=None):
        if rep_state["busy"]:
            return
        rep_state["busy"] = True
        report_btn.config(text="СОБИРАЮ ОТЧЁТ…")
        open_panel("check")

        def build(data):
            if data is None:
                rep_state["busy"] = False
                report_btn.config(text="СОБРАТЬ ОТЧЁТ")
                messagebox.showerror("IPInfo", "Проверка не удалась, отчёт не собран.\n"
                                     "Подробности в журнале:\n%s" % report.logs_dir())
                return
            m = mon_state["mon"]
            events = list(m.events) if m else None
            summary = m.summary() if m else None

            def done(path):
                rep_state["busy"] = False
                report_btn.config(text="СОБРАТЬ ОТЧЁТ")
                if isinstance(path, Exception):
                    messagebox.showerror("IPInfo", "Отчёт не собран: %s" % path)
                    return
                c_put("\nОтчёт: %s\n" % path, "verdict")
                _show_in_explorer(path)
                messagebox.showinfo(
                    "IPInfo - отчёт готов",
                    "Отчёт собран.\n\nФайл: %s\nПапка: %s\n\n"
                    "Папка сейчас откроется, файл в ней выделен.\n"
                    "Отправьте этот zip-файл администратору.\n\n"
                    "Посмотреть отчёт самому: откройте файл с тем же именем и "
                    "расширением .html." % (os.path.basename(path), folder))
            in_background(lambda: report.build_zip(data, cfg, folder=folder, events=events,
                                                   monitor_summary=summary), done)
        start_check(then=build)

    def open_check(_e=None):
        open_panel("check")
        if not run_state["data"] and not run_state["busy"]:
            start_check()

    def open_monitor(_e=None):
        open_panel("monitor")
        if not mon_running():
            start_monitor()

    def on_close():
        if mon_state["mon"]:
            mon_state["mon"].stop()
            mon_state["mon"].thread and mon_state["mon"].thread.join(3)
        root.destroy()

    report_btn.bind("<Button-1>", collect_report)
    reload_btn.bind("<Button-1>", refresh)
    check_btn.bind("<Button-1>", open_check)
    monitor_btn.bind("<Button-1>", open_monitor)
    root.bind("<F5>", refresh)
    root.bind("<Escape>", lambda _e: close_panel() if panel["open"] else on_close())
    root.protocol("WM_DELETE_WINDOW", on_close)
    if cfg.get("autostart", True):
        root.after(500, start_monitor)

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
