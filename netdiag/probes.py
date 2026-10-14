# -*- coding: utf-8 -*-
"""Сетевые пробы: ping, поиск MTU, TCP-порт, DNS.

На Windows ping идёт через IcmpSendEcho (iphlpapi): не нужны права
администратора и не нужно разбирать локализованный вывод ping.exe.
"""

import concurrent.futures
import ctypes
import os
import re
import socket
import subprocess
import time

from .sysutil import IS_WINDOWS

# Коды IP_STATUS из IcmpSendEcho
IP_SUCCESS = 0
_IP_STATUS = {
    11002: "сеть назначения недоступна",
    11003: "узел назначения недоступен",
    11004: "протокол недоступен",
    11005: "порт недоступен",
    11009: "пакет слишком большой",
    11010: "превышено время ожидания",
    11013: "TTL истёк в пути",
    11050: "общая ошибка",
}
IP_PACKET_TOO_BIG = 11009
IP_FLAG_DF = 0x2


class _IP_OPTION_INFORMATION(ctypes.Structure):
    _fields_ = [("Ttl", ctypes.c_ubyte), ("Tos", ctypes.c_ubyte),
                ("Flags", ctypes.c_ubyte), ("OptionsSize", ctypes.c_ubyte),
                ("OptionsData", ctypes.c_void_p)]


class _ICMP_ECHO_REPLY(ctypes.Structure):
    _fields_ = [("Address", ctypes.c_uint32), ("Status", ctypes.c_uint32),
                ("RoundTripTime", ctypes.c_uint32), ("DataSize", ctypes.c_uint16),
                ("Reserved", ctypes.c_uint16), ("Data", ctypes.c_void_p),
                ("Options", _IP_OPTION_INFORMATION)]


_icmp = None


def _icmp_api():
    global _icmp
    if _icmp is None:
        lib = ctypes.WinDLL("iphlpapi", use_last_error=True)
        lib.IcmpCreateFile.restype = ctypes.c_void_p
        lib.IcmpCloseHandle.argtypes = [ctypes.c_void_p]
        lib.IcmpSendEcho.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p,
                                     ctypes.c_uint16, ctypes.POINTER(_IP_OPTION_INFORMATION),
                                     ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32]
        lib.IcmpSendEcho.restype = ctypes.c_uint32
        _icmp = lib
    return _icmp


def resolve4(host, timeout=5):
    """Имя -> IPv4. Возвращает (ip, мс) или (None, текст ошибки)."""
    try:
        socket.inet_aton(host)
        if host.count(".") == 3:
            return host, 0.0
    except OSError:
        pass
    t0 = time.perf_counter()
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    fut = ex.submit(socket.getaddrinfo, host, None, socket.AF_INET, socket.SOCK_STREAM)
    try:
        info = fut.result(timeout=timeout)
        return info[0][4][0], (time.perf_counter() - t0) * 1000
    except concurrent.futures.TimeoutError:
        return None, "DNS не ответил за %d с" % timeout
    except socket.gaierror as e:
        return None, "имя не разрешается (%s)" % (e.strerror or e)
    except Exception as e:
        return None, str(e)
    finally:
        ex.shutdown(wait=False)


def _echo_windows(ip, size, timeout_ms, df):
    """Один ICMP echo. Возвращает (status, rtt_ms)."""
    api = _icmp_api()
    h = api.IcmpCreateFile()
    if not h or h == ctypes.c_void_p(-1).value:
        return 11050, None
    try:
        data = ctypes.create_string_buffer(b"I" * size, size)
        opts = _IP_OPTION_INFORMATION(Ttl=128, Flags=IP_FLAG_DF if df else 0)
        rsize = ctypes.sizeof(_ICMP_ECHO_REPLY) + size + 8 + 64
        reply = ctypes.create_string_buffer(rsize)
        dest = int.from_bytes(socket.inet_aton(ip), "little")
        n = api.IcmpSendEcho(h, dest, data, size, ctypes.byref(opts), reply, rsize, timeout_ms)
        if n == 0:
            return ctypes.get_last_error() or 11050, None
        r = _ICMP_ECHO_REPLY.from_buffer(reply)
        return r.Status, (r.RoundTripTime if r.Status == IP_SUCCESS else None)
    finally:
        api.IcmpCloseHandle(h)


def _echo_posix(ip, size, timeout_ms, df):
    cmd = ["ping", "-n", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), "-s", str(size)]
    if df:
        cmd += ["-M", "do"]
    try:
        p = subprocess.run(cmd + [ip], stdin=subprocess.DEVNULL, capture_output=True, text=True,
                           timeout=timeout_ms / 1000 + 3, env=dict(os.environ, LC_ALL="C"))
    except Exception:
        return 11050, None
    m = re.search(r"time[=<]([\d.]+)", p.stdout)
    if m:
        return IP_SUCCESS, float(m.group(1))
    if "too long" in (p.stdout + p.stderr) or "mtu" in (p.stdout + p.stderr).lower():
        return IP_PACKET_TOO_BIG, None
    return 11010, None


def echo(ip, size=32, timeout_ms=1000, df=False):
    if IS_WINDOWS:
        return _echo_windows(ip, size, timeout_ms, df)
    return _echo_posix(ip, size, timeout_ms, df)


def status_text(status):
    return "ok" if status == IP_SUCCESS else _IP_STATUS.get(status, "ошибка %s" % status)


def ping(ip, count=4, timeout_ms=1000, size=32, interval=0.2):
    """Серия ping. Возвращает словарь с потерями и задержками."""
    rtts, errors = [], {}
    for i in range(count):
        st, rtt = echo(ip, size, timeout_ms)
        if st == IP_SUCCESS:
            rtts.append(rtt)
        else:
            errors[status_text(st)] = errors.get(status_text(st), 0) + 1
        if i + 1 < count:
            time.sleep(interval)
    res = {
        "sent": count, "received": len(rtts),
        "loss_pct": round(100.0 * (count - len(rtts)) / count),
        "errors": errors,
    }
    if rtts:
        res.update(min_ms=min(rtts), avg_ms=round(sum(rtts) / len(rtts), 1), max_ms=max(rtts))
    return res


def find_mtu(ip, lo=548, hi=1472, timeout_ms=1000):
    """Наибольший пакет, который проходит без фрагментации (флаг DF).

    Возвращает MTU пути (данные ICMP + 28 байт заголовков) или None,
    если не проходит даже минимальный пакет.
    """
    def ok(size):
        # два попытки: одиночная потеря не должна занижать MTU
        for _ in range(2):
            st, _rtt = echo(ip, size, timeout_ms, df=True)
            if st == IP_SUCCESS:
                return True
            if st == IP_PACKET_TOO_BIG:
                return False
        return False

    if ok(hi):
        return hi + 28
    if not ok(lo):
        return None
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if ok(mid):
            lo = mid
        else:
            hi = mid
    return lo + 28


def tcp_connect(ip, port, timeout=5):
    """Проверка TCP-порта. Возвращает (True, мс) или (False, текст ошибки)."""
    t0 = time.perf_counter()
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True, round((time.perf_counter() - t0) * 1000, 1)
    except socket.timeout:
        return False, "нет ответа за %d с (порт фильтруется или узел недоступен)" % timeout
    except ConnectionRefusedError:
        return False, "соединение отклонено (порт закрыт)"
    except OSError as e:
        return False, e.strerror or str(e)


def _cert_info(der):
    """Кому выдан сертификат: {'subject', 'issuer', 'names'} (разбор средствами Python)."""
    import os
    import ssl
    import tempfile
    info = {"subject": "", "issuer": "", "names": []}
    try:
        fd, path = tempfile.mkstemp(suffix=".pem")
        with os.fdopen(fd, "w") as f:
            f.write(ssl.DER_cert_to_PEM_cert(der))
        try:
            dec = ssl._ssl._test_decode_cert(path)
        finally:
            os.remove(path)
    except Exception:
        return info

    def cn(rdns):
        for rdn in rdns or ():
            for k, v in rdn:
                if k in ("commonName", "organizationName"):
                    return v
        return ""
    info["subject"] = cn(dec.get("subject"))
    info["issuer"] = cn(dec.get("issuer"))
    info["names"] = [v for k, v in dec.get("subjectAltName", ()) if k == "DNS"] or \
        ([info["subject"]] if info["subject"] else [])
    return info


def tls_probe(ip, port, sni=None, timeout=6):
    """Обычное TLS-рукопожатие с адресом: что ответил сервер и чей у него сертификат.

    Сертификат не проверяется на доверие - нужно только понять, кто на том конце.
    Возвращает {'ok', 'version', 'subject', 'issuer', 'names'} или {'ok': False, 'error'}.
    """
    import ssl
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni) as s:
                der = s.getpeercert(binary_form=True)
                res = {"ok": True, "version": s.version()}
                res.update(_cert_info(der) if der else {"subject": "", "issuer": "",
                                                        "names": []})
                return res
    except ssl.SSLError as e:
        reason = getattr(e, "reason", None) or str(e)
        return {"ok": False, "error": str(reason).lower().replace("_", " ")}
    except socket.timeout:
        return {"ok": False, "error": "нет ответа на рукопожатие за %d с" % timeout}
    except OSError as e:
        return {"ok": False, "error": e.strerror or str(e)}


def cert_matches(names, host):
    """Подходит ли сертификат для имени host (с учётом *.domain)."""
    host = (host or "").lower()
    for n in names or ():
        n = n.lower()
        if n == host or (n.startswith("*.") and host.endswith(n[1:]) and
                         host.count(".") == n.count(".")):
            return True
    return False


EXTERNAL_IP_URLS = ("https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com")


def external_ip(timeout=4):
    """Внешний IP. Возвращает (ip, None) или (None, причина для каждого сервиса)."""
    import ipaddress
    import urllib.request
    errors = []
    for url in EXTERNAL_IP_URLS:
        try:
            with urllib.request.urlopen(url, timeout=timeout) as r:
                text = r.read(100).decode("utf-8", "ignore").strip()
            ipaddress.ip_address(text)
            return text, None
        except ValueError:
            errors.append("%s: ответ не похож на IP" % url)
        except Exception as e:
            reason = getattr(e, "reason", None) or e
            errors.append("%s: %s" % (url, reason))
    return None, "; ".join(errors)


def resolve_all(host, timeout=5):
    """Все IPv4-адреса имени (у сервера может быть несколько A-записей).

    Возвращает (список адресов, мс) или ([], текст ошибки).
    """
    try:
        socket.inet_aton(host)
        if host.count(".") == 3:
            return [host], 0.0
    except OSError:
        pass
    t0 = time.perf_counter()
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    fut = ex.submit(socket.getaddrinfo, host, None, socket.AF_INET, socket.SOCK_STREAM)
    try:
        info = fut.result(timeout=timeout)
    except concurrent.futures.TimeoutError:
        return [], "DNS не ответил за %d с" % timeout
    except socket.gaierror as e:
        return [], "имя не разрешается (%s)" % (e.strerror or e)
    except Exception as e:
        return [], str(e)
    finally:
        ex.shutdown(wait=False)
    ips = []
    for item in info:
        ip = item[4][0]
        if ip not in ips:
            ips.append(ip)
    return ips, (time.perf_counter() - t0) * 1000
