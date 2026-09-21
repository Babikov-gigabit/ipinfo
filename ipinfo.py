#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ipinfo - показывает IP-адреса всех сетевых адаптеров.

Только стандартная библиотека Python (ctypes / tkinter / urllib).

Запуск:
    python ipinfo.py            # окно
    python ipinfo.py --cli      # консоль
    python ipinfo.py --all      # включая выключенные адаптеры и loopback
    python ipinfo.py --no-net   # не запрашивать внешний IP
    python ipinfo.py --json     # вывод в JSON
"""

import argparse
import json
import os
import platform
import re
import socket
import subprocess
import sys

IS_WINDOWS = platform.system() == "Windows"

ICON_NAME = "ip-icon.ico"


def resource_path(name):
    """Путь к ресурсу рядом со скриптом или внутри собранного exe."""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, name)


# --------------------------------------------------------------------------
# Windows: GetAdaptersAddresses через ctypes.
# Не зависит от языка системы (в отличие от разбора вывода ipconfig).
# --------------------------------------------------------------------------
def _adapters_windows():
    import ctypes
    from ctypes import wintypes

    wsz = ctypes.c_wchar_p
    ULONG = wintypes.ULONG
    ULONG64 = ctypes.c_uint64

    class SOCKADDR(ctypes.Structure):
        _fields_ = [("sa_family", ctypes.c_ushort), ("sa_data", ctypes.c_ubyte * 26)]

    class SOCKET_ADDRESS(ctypes.Structure):
        _fields_ = [("lpSockaddr", ctypes.POINTER(SOCKADDR)),
                    ("iSockaddrLength", ctypes.c_int)]

    class IP_ADAPTER_UNICAST_ADDRESS(ctypes.Structure):
        pass

    IP_ADAPTER_UNICAST_ADDRESS._fields_ = [
        ("Length", ULONG), ("Flags", wintypes.DWORD),
        ("Next", ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
        ("Address", SOCKET_ADDRESS),
        ("PrefixOrigin", ctypes.c_int), ("SuffixOrigin", ctypes.c_int),
        ("DadState", ctypes.c_int),
        ("ValidLifetime", ULONG), ("PreferredLifetime", ULONG),
        ("LeaseLifetime", ULONG), ("OnLinkPrefixLength", ctypes.c_ubyte),
    ]

    class IP_ADAPTER_ADDR(ctypes.Structure):
        """Общая форма для DNS / Gateway / Anycast / Multicast / WINS."""
        pass

    IP_ADAPTER_ADDR._fields_ = [
        ("Length", ULONG), ("Reserved", wintypes.DWORD),
        ("Next", ctypes.POINTER(IP_ADAPTER_ADDR)),
        ("Address", SOCKET_ADDRESS),
    ]

    class IP_ADAPTER_ADDRESSES(ctypes.Structure):
        pass

    IP_ADAPTER_ADDRESSES._fields_ = [
        ("Length", ULONG), ("IfIndex", ULONG),
        ("Next", ctypes.POINTER(IP_ADAPTER_ADDRESSES)),
        ("AdapterName", ctypes.c_char_p),
        ("FirstUnicastAddress", ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
        ("FirstAnycastAddress", ctypes.POINTER(IP_ADAPTER_ADDR)),
        ("FirstMulticastAddress", ctypes.POINTER(IP_ADAPTER_ADDR)),
        ("FirstDnsServerAddress", ctypes.POINTER(IP_ADAPTER_ADDR)),
        ("DnsSuffix", wsz), ("Description", wsz), ("FriendlyName", wsz),
        ("PhysicalAddress", ctypes.c_ubyte * 8), ("PhysicalAddressLength", ULONG),
        ("Flags", ULONG), ("Mtu", ULONG), ("IfType", ULONG), ("OperStatus", ctypes.c_int),
        ("Ipv6IfIndex", ULONG), ("ZoneIndices", ULONG * 16),
        ("FirstPrefix", ctypes.c_void_p),
        ("TransmitLinkSpeed", ULONG64), ("ReceiveLinkSpeed", ULONG64),
        ("FirstWinsServerAddress", ctypes.POINTER(IP_ADAPTER_ADDR)),
        ("FirstGatewayAddress", ctypes.POINTER(IP_ADAPTER_ADDR)),
        ("Ipv4Metric", ULONG), ("Ipv6Metric", ULONG),
    ]

    def sockaddr_to_ip(sa_ptr):
        if not sa_ptr:
            return None
        sa = sa_ptr.contents
        raw = bytes(bytearray(sa.sa_data))
        if sa.sa_family == socket.AF_INET:          # sin_addr на смещении 4
            return socket.inet_ntop(socket.AF_INET, raw[2:6])
        if sa.sa_family == socket.AF_INET6:         # sin6_addr на смещении 8
            return socket.inet_ntop(socket.AF_INET6, raw[6:22])
        return None

    def walk(ptr):
        while ptr:
            node = ptr.contents
            yield node
            ptr = node.Next

    GAA_FLAG_SKIP_ANYCAST = 0x0002
    GAA_FLAG_SKIP_MULTICAST = 0x0004
    GAA_FLAG_INCLUDE_GATEWAYS = 0x0080
    flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_INCLUDE_GATEWAYS

    GetAdaptersAddresses = ctypes.windll.iphlpapi.GetAdaptersAddresses
    size = ULONG(15 * 1024)
    buf = None
    for _ in range(4):
        buf = ctypes.create_string_buffer(size.value)
        rc = GetAdaptersAddresses(0, flags, None,
                                  ctypes.cast(buf, ctypes.POINTER(IP_ADAPTER_ADDRESSES)),
                                  ctypes.byref(size))
        if rc == 0:
            break
        if rc != 111:  # ERROR_BUFFER_OVERFLOW
            raise OSError("GetAdaptersAddresses failed, code %d" % rc)
    else:
        raise OSError("GetAdaptersAddresses: не удалось выделить буфер")

    OPER = {1: "Up", 2: "Down", 3: "Testing", 4: "Unknown",
            5: "Dormant", 6: "NotPresent", 7: "LowerLayerDown"}
    IFTYPE = {6: "Ethernet", 23: "PPP", 24: "Loopback", 53: "Виртуальный",
              71: "Wi-Fi", 131: "Tunnel", 144: "IEEE1394", 237: "IEEE1394"}

    result = []
    for a in walk(ctypes.cast(buf, ctypes.POINTER(IP_ADAPTER_ADDRESSES))):
        ipv4, ipv6 = [], []
        for u in walk(a.FirstUnicastAddress):
            ip = sockaddr_to_ip(u.Address.lpSockaddr)
            if not ip:
                continue
            entry = "%s/%d" % (ip, u.OnLinkPrefixLength)
            (ipv6 if ":" in ip else ipv4).append(entry)

        gws = [ip for ip in (sockaddr_to_ip(g.Address.lpSockaddr)
                             for g in walk(a.FirstGatewayAddress)) if ip]
        dns = [ip for ip in (sockaddr_to_ip(d.Address.lpSockaddr)
                             for d in walk(a.FirstDnsServerAddress)) if ip]

        mac = ":".join("%02X" % b for b in a.PhysicalAddress[:a.PhysicalAddressLength])
        speed = a.TransmitLinkSpeed
        if speed in (0, 0xFFFFFFFFFFFFFFFF):
            speed_s = "-"
        elif speed >= 10 ** 9:
            speed_s = "%.0f Gbps" % (speed / 10 ** 9)
        else:
            speed_s = "%.0f Mbps" % (speed / 10 ** 6)

        result.append({
            "name": a.FriendlyName or "",
            "description": a.Description or "",
            "type": IFTYPE.get(a.IfType, "type %d" % a.IfType),
            "status": OPER.get(a.OperStatus, "?"),
            "up": a.OperStatus == 1,
            "ipv4": ipv4, "ipv6": ipv6,
            "gateway": gws, "dns": dns,
            "mac": mac or "-",
            "mtu": a.Mtu if a.Mtu < 0xFFFFFFFF else 0,
            "speed": speed_s,
            "loopback": a.IfType == 24,
        })
    return result


# --------------------------------------------------------------------------
# Linux / macOS: разбор вывода ip / ifconfig (вывод не локализуется).
# --------------------------------------------------------------------------
def _run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return ""


def _adapters_posix():
    ifaces = {}

    def get(name):
        return ifaces.setdefault(name, {
            "name": name, "description": "", "type": "-", "status": "Unknown",
            "up": False, "ipv4": [], "ipv6": [], "gateway": [], "dns": [],
            "mac": "-", "mtu": 0, "speed": "-",
            "loopback": name in ("lo", "lo0"),
        })

    out = _run(["ip", "-o", "addr", "show"])
    if out:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            it = get(parts[1])
            fam, addr = parts[2], parts[3]
            if fam == "inet":
                it["ipv4"].append(addr)
            elif fam == "inet6":
                it["ipv6"].append(addr)
        for line in _run(["ip", "-o", "link", "show"]).splitlines():
            m = re.match(r"\d+:\s+([^:@]+)[:@].*?<([^>]*)>.*?mtu (\d+)", line)
            if not m:
                continue
            it = get(m.group(1))
            it["up"] = "UP" in m.group(2).split(",")
            it["status"] = "Up" if it["up"] else "Down"
            it["mtu"] = int(m.group(3))
            mac = re.search(r"link/\w+\s+([0-9a-f:]{17})", line)
            if mac:
                it["mac"] = mac.group(1).upper()
        for line in _run(["ip", "route", "show", "default"]).splitlines():
            m = re.search(r"default via (\S+) dev (\S+)", line)
            if m:
                get(m.group(2))["gateway"].append(m.group(1))
    else:
        # macOS / системы без iproute2
        cur = None
        for line in _run(["ifconfig", "-a"]).splitlines():
            m = re.match(r"^(\S+):\s+flags=\d+<([^>]*)>.*mtu (\d+)", line)
            if m:
                cur = get(m.group(1))
                cur["up"] = "UP" in m.group(2).split(",")
                cur["status"] = "Up" if cur["up"] else "Down"
                cur["mtu"] = int(m.group(3))
                continue
            if cur is None:
                continue
            s = line.strip()
            if s.startswith("inet "):
                cur["ipv4"].append(s.split()[1])
            elif s.startswith("inet6 "):
                cur["ipv6"].append(s.split()[1].split("%")[0])
            elif s.startswith("ether "):
                cur["mac"] = s.split()[1].upper()
        for line in _run(["netstat", "-rn"]).splitlines():
            p = line.split()
            if len(p) >= 4 and p[0] in ("default", "0.0.0.0") and p[-1] in ifaces:
                ifaces[p[-1]]["gateway"].append(p[1])

    try:
        with open("/etc/resolv.conf") as f:
            servers = [ln.split()[1] for ln in f if ln.startswith("nameserver")]
        for it in ifaces.values():
            if it["up"]:
                it["dns"] = servers
    except Exception:
        pass

    return list(ifaces.values())


def get_adapters(include_down=False):
    data = _adapters_windows() if IS_WINDOWS else _adapters_posix()
    data.sort(key=lambda x: (not x["up"], x["name"]))
    if include_down:
        return data
    return [a for a in data
            if a["up"] and not a.get("loopback") and (a["ipv4"] or a["ipv6"])]


def get_external_ip(timeout=4):
    import urllib.request
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"):
        try:
            with urllib.request.urlopen(url, timeout=timeout) as r:
                ip = r.read().decode("utf-8", "ignore").strip()
            if ip:
                return ip
        except Exception:
            continue
    return "нет связи"


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


def run_gui(include_down, want_external):
    import threading
    import tkinter as tk
    from tkinter import font as tkfont

    root = tk.Tk()
    root.title("IP")
    root.configure(bg=BG)
    root.geometry("400x480")
    root.minsize(340, 300)
    try:
        root.iconbitmap(resource_path(ICON_NAME))
    except Exception:
        pass

    family = "Segoe UI" if "Segoe UI" in tkfont.families() else "Helvetica"
    f_label = (family, 8)
    f_ip = (family, 19)
    f_meta = (family, 8)
    f_head = (family, 9)

    state = {"toast": None}

    # --- шапка ---------------------------------------------------------
    head = tk.Frame(root, bg=BG)
    head.pack(fill="x", padx=22, pady=(18, 6))

    tk.Label(head, text="СЕТЬ", font=(family, 8, "bold"), fg=FG_MUTED, bg=BG).pack(side="left")

    reload_btn = tk.Label(head, text="↻", font=(family, 13), fg=FG_MUTED, bg=BG, cursor="hand2")
    reload_btn.pack(side="right")

    # --- прокручиваемая область ----------------------------------------
    canvas = tk.Canvas(root, bg=BG, highlightthickness=0, bd=0)
    canvas.pack(fill="both", expand=True)
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

    root.bind_all("<MouseWheel>", on_wheel)

    # --- подвал --------------------------------------------------------
    foot = tk.Frame(root, bg=BG)
    foot.pack(fill="x", side="bottom")
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
    def add_card(a, first):
        if not first:
            tk.Frame(body, bg=RULE, height=1).pack(fill="x", padx=22)

        card = tk.Frame(body, bg=BG, cursor="hand2")
        card.pack(fill="x")
        inner = tk.Frame(card, bg=BG)
        inner.pack(fill="x", padx=22, pady=13)

        top = tk.Frame(inner, bg=BG)
        top.pack(fill="x")
        tk.Label(top, text=a["name"].upper(), font=f_label, fg=FG_MUTED, bg=BG,
                 anchor="w").pack(side="left")
        tk.Label(top, text="●", font=(family, 7), bg=BG,
                 fg=DOT_UP if a["up"] else DOT_DOWN).pack(side="right")

        ip = a["ipv4"][0].split("/")[0] if a["ipv4"] else (
            a["ipv6"][0].split("/")[0] if a["ipv6"] else "—")
        tk.Label(inner, text=ip, font=f_ip, fg=FG, bg=BG, anchor="w").pack(fill="x", pady=(1, 2))

        bits = []
        if a["ipv4"] and "/" in a["ipv4"][0]:
            bits.append("/" + a["ipv4"][0].split("/")[1])
        if a["gateway"]:
            bits.append("шлюз " + a["gateway"][0])
        tk.Label(inner, text="   ·   ".join(bits), font=f_meta, fg=FG_MUTED, bg=BG,
                 anchor="w").pack(fill="x")

        def paint(color):
            for w in (card, inner, top) + tuple(inner.winfo_children()) + tuple(top.winfo_children()):
                try:
                    w.configure(bg=color)
                except tk.TclError:
                    pass

        def copy(_e=None):
            root.clipboard_clear()
            root.clipboard_append(ip)
            toast("скопировано  " + ip)

        for w in (card, inner, top) + tuple(inner.winfo_children()) + tuple(top.winfo_children()):
            w.bind("<Button-1>", copy)
            w.bind("<Enter>", lambda _e: paint(BG_HOVER))
            w.bind("<Leave>", lambda _e: paint(BG))

    # --- обновление ----------------------------------------------------
    def refresh(_e=None):
        for w in body.winfo_children():
            w.destroy()
        adapters = get_adapters(include_down=include_down)
        if not adapters:
            tk.Label(body, text="адаптеров с IP нет", font=f_head, fg=FG_MUTED,
                     bg=BG).pack(pady=40)
        for i, a in enumerate(adapters):
            add_card(a, first=(i == 0))
        on_body_configure()

        if want_external:
            ext_label.config(text="внешний  …")

            def fetch():
                ip = get_external_ip()
                root.after(0, lambda: ext_label.config(text="внешний  " + ip))

            threading.Thread(target=fetch, daemon=True).start()
        else:
            ext_label.config(text="")

    reload_btn.bind("<Button-1>", refresh)
    reload_btn.bind("<Enter>", lambda _e: reload_btn.config(fg=FG))
    reload_btn.bind("<Leave>", lambda _e: reload_btn.config(fg=FG_MUTED))
    root.bind("<F5>", refresh)
    root.bind("<Escape>", lambda _e: root.destroy())

    refresh()
    root.mainloop()


def main():
    p = argparse.ArgumentParser(description="Показывает IP всех сетевых адаптеров")
    p.add_argument("--cli", action="store_true", help="консольный вывод вместо окна")
    p.add_argument("--all", action="store_true", help="включая выключенные адаптеры")
    p.add_argument("--no-net", action="store_true", help="не запрашивать внешний IP")
    p.add_argument("--json", action="store_true", help="вывод в формате JSON")
    args = p.parse_args()

    if args.json:
        data = {"adapters": get_adapters(include_down=args.all)}
        if not args.no_net:
            data["external_ip"] = get_external_ip()
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return

    if not args.cli:
        try:
            run_gui(include_down=args.all, want_external=not args.no_net)
            return
        except Exception as e:
            print("GUI недоступен (%s), вывожу в консоль.\n" % e)

    print_console(get_adapters(include_down=args.all),
                  external=None if args.no_net else get_external_ip())


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
