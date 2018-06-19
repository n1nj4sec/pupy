# -*- encoding: utf-8 -*-

from ctypes import Structure, windll, c_uint, sizeof, byref

class LASTINPUTINFO(Structure):
    _fields_ = [
        ('cbSize', c_uint),
        ('dwTime', c_uint),
    ]

GetLastInputInfo = windll.user32.GetLastInputInfo
GetTickCount = windll.kernel32.GetTickCount

def get_gui_idle(display=None):
    lastInputInfo = LASTINPUTINFO()
    lastInputInfo.cbSize = sizeof(lastInputInfo)
    GetLastInputInfo(byref(lastInputInfo))
    millis = GetTickCount() - lastInputInfo.dwTime
    return int(millis / 1000)

def get_idle():
    return get_gui_idle()
