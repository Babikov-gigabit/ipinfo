# -*- coding: utf-8 -*-
"""Сетевые адаптеры, счётчики трафика и выбор маршрута.

На Windows всё берётся из WinAPI (iphlpapi) через ctypes: не зависит
от языка системы, в отличие от разбора вывода ipconfig.
"""

import ctypes
import ipaddress
import re
import socket

from .sysutil import IS_WINDOWS, run as _run_cmd


def _run(cmd):
    out = _run_cmd(cmd, timeout=5)
    # sysutil.run сообщает об ошибке запуска текстом в скобках - тут он не нужен
    return "" if out.startswith("(") else out


# --------------------------------------------------------------------------
# Windows: GetAdaptersAddresses через ctypes.
# Не зависит от языка системы (в отличие от разбора вывода ipconfig).
# --------------------------------------------------------------------------
def _adapters_windows():
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
              71: "Wi-Fi", 131: "Tunnel", 144: "IEEE1394", 237: "WiMAX"}

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
            "index": a.IfIndex,
            "name": a.FriendlyName or "",
            "description": a.Description or "",
            "type": IFTYPE.get(a.IfType, "type %d" % a.IfType),
            "iftype": a.IfType,
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
def _adapters_posix():
    ifaces = {}

    def get(name):
        return ifaces.setdefault(name, {
            "index": 0, "iftype": 0,
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
            it["index"] = int(line.split(":", 1)[0])
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
    """Список адаптеров. include_down=False - только активные с IP-адресом."""
    data = _adapters_windows() if IS_WINDOWS else _adapters_posix()
    data.sort(key=lambda x: (not x["up"], x["name"]))
    if include_down:
        return data
    return [a for a in data
            if a["up"] and not a.get("loopback") and (a["ipv4"] or a["ipv6"])]


# --------------------------------------------------------------------------
# Разбор адресов
# --------------------------------------------------------------------------
def ipv4_addrs(adapter):
    """IPv4-адреса адаптера без маски."""
    return [x.split("/")[0] for x in adapter.get("ipv4", [])]


def is_apipa(ip):
    """169.254.x.x - Windows сама назначила адрес, потому что DHCP не ответил."""
    return ip.startswith("169.254.")


def prefix_to_mask(prefix):
    try:
        return str(ipaddress.IPv4Network("0.0.0.0/%s" % prefix).netmask)
    except ValueError:
        return ""


def networks(adapter):
    """IPv4-сети адаптера (ip/префикс -> IPv4Network)."""
    nets = []
    for x in adapter.get("ipv4", []):
        try:
            nets.append(ipaddress.IPv4Interface(x).network)
        except ValueError:
            pass
    return nets


# --------------------------------------------------------------------------
# Счётчики трафика интерфейса: GetIfEntry2 (MIB_IF_ROW2)
# --------------------------------------------------------------------------
class _GUID(ctypes.Structure):
    _fields_ = [("Data1", ctypes.c_uint32), ("Data2", ctypes.c_uint16),
                ("Data3", ctypes.c_uint16), ("Data4", ctypes.c_ubyte * 8)]


class MIB_IF_ROW2(ctypes.Structure):
    # WCHAR задан как c_uint16: c_wchar на Linux 4 байта, а размер структуры
    # проверяется тестом (1352 байта, как в Windows x64).
    _fields_ = [
        ("InterfaceLuid", ctypes.c_uint64),
        ("InterfaceIndex", ctypes.c_uint32),
        ("InterfaceGuid", _GUID),
        ("Alias", ctypes.c_uint16 * 257),
        ("Description", ctypes.c_uint16 * 257),
        ("PhysicalAddressLength", ctypes.c_uint32),
        ("PhysicalAddress", ctypes.c_ubyte * 32),
        ("PermanentPhysicalAddress", ctypes.c_ubyte * 32),
        ("Mtu", ctypes.c_uint32),
        ("Type", ctypes.c_uint32),
        ("TunnelType", ctypes.c_int),
        ("MediaType", ctypes.c_int),
        ("PhysicalMediumType", ctypes.c_int),
        ("AccessType", ctypes.c_int),
        ("DirectionType", ctypes.c_int),
        ("InterfaceAndOperStatusFlags", ctypes.c_ubyte),
        ("OperStatus", ctypes.c_int),
        ("AdminStatus", ctypes.c_int),
        ("MediaConnectState", ctypes.c_int),
        ("NetworkGuid", _GUID),
        ("ConnectionType", ctypes.c_int),
        ("TransmitLinkSpeed", ctypes.c_uint64),
        ("ReceiveLinkSpeed", ctypes.c_uint64),
        ("InOctets", ctypes.c_uint64),
        ("InUcastPkts", ctypes.c_uint64),
        ("InNUcastPkts", ctypes.c_uint64),
        ("InDiscards", ctypes.c_uint64),
        ("InErrors", ctypes.c_uint64),
        ("InUnknownProtos", ctypes.c_uint64),
        ("InUcastOctets", ctypes.c_uint64),
        ("InMulticastOctets", ctypes.c_uint64),
        ("InBroadcastOctets", ctypes.c_uint64),
        ("OutOctets", ctypes.c_uint64),
        ("OutUcastPkts", ctypes.c_uint64),
        ("OutNUcastPkts", ctypes.c_uint64),
        ("OutDiscards", ctypes.c_uint64),
        ("OutErrors", ctypes.c_uint64),
        ("OutUcastOctets", ctypes.c_uint64),
        ("OutMulticastOctets", ctypes.c_uint64),
        ("OutBroadcastOctets", ctypes.c_uint64),
        ("OutQLen", ctypes.c_uint64),
    ]


def if_stats(index):
    """Счётчики интерфейса по индексу: байты, пакеты, ошибки. None, если нет данных."""
    if IS_WINDOWS:
        row = MIB_IF_ROW2()
        row.InterfaceIndex = index
        try:
            if ctypes.windll.iphlpapi.GetIfEntry2(ctypes.byref(row)) != 0:
                return None
        except Exception:
            return None
        return {
            "rx_bytes": row.InOctets, "tx_bytes": row.OutOctets,
            "rx_packets": row.InUcastPkts + row.InNUcastPkts,
            "tx_packets": row.OutUcastPkts + row.OutNUcastPkts,
            "rx_errors": row.InErrors, "tx_errors": row.OutErrors,
            "rx_discards": row.InDiscards, "tx_discards": row.OutDiscards,
        }
    return _if_stats_linux(index)


def _if_stats_linux(index):
    try:
        import os
        for name in os.listdir("/sys/class/net"):
            base = "/sys/class/net/%s/" % name
            with open(base + "ifindex") as f:
                if int(f.read()) != index:
                    continue

            def rd(k):
                with open(base + "statistics/" + k) as f:
                    return int(f.read())
            return {
                "rx_bytes": rd("rx_bytes"), "tx_bytes": rd("tx_bytes"),
                "rx_packets": rd("rx_packets"), "tx_packets": rd("tx_packets"),
                "rx_errors": rd("rx_errors"), "tx_errors": rd("tx_errors"),
                "rx_discards": rd("rx_dropped"), "tx_discards": rd("tx_dropped"),
            }
    except Exception:
        pass
    return None


# --------------------------------------------------------------------------
# Через какой интерфейс уйдёт пакет к адресу
# --------------------------------------------------------------------------
def best_interface(ip):
    """Индекс интерфейса, через который Windows отправит пакет на ip (IPv4).

    Нужен, чтобы поймать конфликт: домашняя сеть 10.x перехватывает трафик,
    который должен идти в туннель.
    """
    try:
        dest = int.from_bytes(socket.inet_aton(ip), "little")
    except OSError:
        return None
    if IS_WINDOWS:
        idx = ctypes.c_ulong(0)
        try:
            rc = ctypes.windll.iphlpapi.GetBestInterface(ctypes.c_ulong(dest), ctypes.byref(idx))
        except Exception:
            return None
        return idx.value if rc == 0 else None
    out = _run(["ip", "-o", "route", "get", ip])
    m = re.search(r"\bdev (\S+)", out)
    if not m:
        return None
    try:
        with open("/sys/class/net/%s/ifindex" % m.group(1)) as f:
            return int(f.read())
    except Exception:
        return None


# --------------------------------------------------------------------------
# Установленные TCP-соединения с процессом (GetExtendedTcpTable): дёшево,
# можно опрашивать каждые пару секунд, в отличие от Get-NetTCPConnection.
# --------------------------------------------------------------------------
_proc_names = {}


def _process_name(pid):
    """(имя без .exe, полный путь) процесса."""
    if pid in _proc_names:
        return _proc_names[pid]
    name = path = ""
    k32 = ctypes.windll.kernel32
    h = k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if h:
        try:
            buf = ctypes.create_unicode_buffer(1024)
            size = ctypes.c_ulong(len(buf))
            if k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
                path = buf.value
                name = re.split(r"[\\/]", path)[-1]
                if name.lower().endswith(".exe"):
                    name = name[:-4]
        finally:
            k32.CloseHandle(h)
    if len(_proc_names) > 2000:
        _proc_names.clear()
    _proc_names[pid] = (name, path)
    return name, path


TCP_STATES = {2: "syn_sent", 5: "established"}


def tcp_connections(syn_sent=False):
    """Установленные TCP-соединения IPv4: [{remote, rport, local, lport, pid, process, path,
    state}]. С syn_sent=True - ещё и попытки подключения, на которые пока нет ответа.

    None, если прочитать не удалось (или не Windows).
    """
    if not IS_WINDOWS:
        return None
    import struct
    func = ctypes.windll.iphlpapi.GetExtendedTcpTable
    size = ctypes.c_ulong(0)
    buf = None
    for _ in range(5):
        buf = ctypes.create_string_buffer(size.value or 1)
        # AF_INET=2, TCP_TABLE_OWNER_PID_CONNECTIONS=4
        rc = func(buf, ctypes.byref(size), False, 2, 4, 0)
        if rc == 0:
            break
        if rc != 122:  # ERROR_INSUFFICIENT_BUFFER
            return None
    else:
        return None
    raw = buf.raw
    count = struct.unpack_from("<I", raw, 0)[0]
    res = []
    for i in range(count):
        state, laddr, lport, raddr, rport, pid = struct.unpack_from("<6I", raw, 4 + i * 24)
        if state != 5 and not (syn_sent and state == 2):  # ESTAB / SYN_SENT
            continue
        name, path = _process_name(pid)
        res.append({
            "remote": socket.inet_ntoa(struct.pack("<I", raddr)),
            "rport": socket.ntohs(rport & 0xFFFF),
            "local": socket.inet_ntoa(struct.pack("<I", laddr)),
            "lport": socket.ntohs(lport & 0xFFFF),
            "pid": pid, "process": name, "path": path, "state": TCP_STATES[state],
        })
    return res


def udp_pids():
    """Процессы, у которых открыты UDP-сокеты (IPv4 и IPv6): {pid}. None вне Windows."""
    if not IS_WINDOWS:
        return None
    import struct
    func = ctypes.windll.iphlpapi.GetExtendedUdpTable
    pids = set()
    # AF_INET=2: строка 12 байт, AF_INET6=23: 28 байт; UDP_TABLE_OWNER_PID=1
    for family, row in ((2, 12), (23, 28)):
        size = ctypes.c_ulong(0)
        buf = None
        for _ in range(5):
            buf = ctypes.create_string_buffer(size.value or 1)
            rc = func(buf, ctypes.byref(size), False, family, 1, 0)
            if rc == 0:
                break
            if rc != 122:
                buf = None
                break
        else:
            buf = None
        if buf is None:
            continue
        raw = buf.raw
        count = struct.unpack_from("<I", raw, 0)[0]
        for i in range(count):
            pids.add(struct.unpack_from("<I", raw, 4 + i * row + row - 4)[0])
    return pids
