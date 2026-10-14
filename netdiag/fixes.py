# -*- coding: utf-8 -*-
"""Исправления, которые включаются кнопкой на вкладке FIX.

RDP-FIX: клиент RDP (mstsc) по умолчанию перестаёт отрисовывать сеанс,
когда окно свёрнуто. RemoteDesktop_SuppressWhenMinimized = 2 оставляет
сеанс активным в свёрнутом окне. Без параметра - стандартное поведение.
Запись в HKLM требует прав администратора: без них reg.exe запускается
через запрос UAC.
"""

from .sysutil import IS_WINDOWS, run

RDP_KEY = r"Software\Microsoft\Terminal Server Client"
RDP_VALUE = "RemoteDesktop_SuppressWhenMinimized"
RDP_FIX_DATA = 2
REG_PATH = r"HKLM\Software\Microsoft\Terminal Server Client"


def _winreg():
    import winreg
    return winreg


def rdp_fix_state():
    """Текущее значение параметра: число или None (не задан - стандартно)."""
    if not IS_WINDOWS:
        return None
    winreg = _winreg()
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, RDP_KEY, 0,
                            winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
            return winreg.QueryValueEx(k, RDP_VALUE)[0]
    except OSError:
        return None


def describe_state(value):
    if value is None:
        return "не задан - стандартное поведение (свёрнутый сеанс RDP не отрисовывается)"
    if value == RDP_FIX_DATA:
        return "%s = 2 - исправление включено (сеанс не засыпает в свёрнутом окне)" % RDP_VALUE
    return "%s = %s" % (RDP_VALUE, value)


def reg_args(enable):
    """Аргументы reg.exe для включения или отмены исправления."""
    if enable:
        return ["add", REG_PATH, "/v", RDP_VALUE, "/t", "REG_DWORD", "/d", str(RDP_FIX_DATA),
                "/f", "/reg:64"]
    return ["delete", REG_PATH, "/v", RDP_VALUE, "/f", "/reg:64"]


def _direct(enable):
    winreg = _winreg()
    access = winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY
    if enable:
        with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, RDP_KEY, 0, access) as k:
            winreg.SetValueEx(k, RDP_VALUE, 0, winreg.REG_DWORD, RDP_FIX_DATA)
    else:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, RDP_KEY, 0, access) as k:
                winreg.DeleteValue(k, RDP_VALUE)
        except FileNotFoundError:
            pass


def _elevated(enable):
    """reg.exe с правами администратора (появится запрос UAC), ждём завершения."""
    args = ",".join("'%s'" % a.replace("'", "''") for a in reg_args(enable))
    run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
         "Start-Process -FilePath reg.exe -ArgumentList %s -Verb RunAs -Wait "
         "-WindowStyle Hidden" % args], timeout=120)


def set_rdp_fix(enable):
    """Включает (enable=True) или отменяет исправление. Возвращает (успех, текст)."""
    if not IS_WINDOWS:
        return False, "работает только в Windows"
    try:
        _direct(enable)
    except PermissionError:
        _elevated(enable)
    except OSError as e:
        return False, "не удалось изменить реестр: %s" % e
    value = rdp_fix_state()
    ok = (value == RDP_FIX_DATA) if enable else (value is None)
    if not ok:
        return False, "параметр не изменён: нужны права администратора (подтвердите запрос " \
                      "Windows) или запустите IPInfo от имени администратора"
    return True, ("исправление включено" if enable else "возвращено стандартное значение") + \
        ". Чтобы оно подействовало, закройте все окна RDP и подключитесь заново."
