#code from http://tiger-222.fr/?d=2013/08/05/21/35/31-windows-capture-decran

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


# Initilisations
SM_XVIRTUALSCREEN = 76  # Coordonnée gauche *
SM_YVIRTUALSCREEN = 77  # Coordonnée haute *
SM_CXVIRTUALSCREEN = 78  # Largeur *
SM_CYVIRTUALSCREEN = 79  # Hauteur *
SRCCOPY = 0xCC0020  # Code de copie pour la fonction BitBlt()
DIB_RGB_COLORS = 0

GetSystemMetrics = windll.user32.GetSystemMetrics
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


def enum_display_monitors(oneshot=False):

    def _callback(monitor, dc, rect, data):
        rct = rect.contents
        results.append({
            b'left'  : int(rct.left),
            b'top'   : int(rct.top),
            b'width' : int(rct.right - rct.left),
            b'height': int(rct.bottom -rct.top)
        })
        return 1

    results = []
    if oneshot:
        left = GetSystemMetrics(SM_XVIRTUALSCREEN)
        right = GetSystemMetrics(SM_CXVIRTUALSCREEN)
        top = GetSystemMetrics(SM_YVIRTUALSCREEN)
        bottom = GetSystemMetrics(SM_CYVIRTUALSCREEN)
        results.append({
            b'left'  : int(left),
            b'top'   : int(top),
            b'width' : int(right - left),
            b'height': int(bottom - top)
        })
    else:
        callback = MONITORENUMPROC(_callback)
        EnumDisplayMonitors(0, 0, callback, 0)
    return results


def get_pixels(monitor):

    width, height = monitor['width'], monitor['height']
    left, top = monitor['left'], monitor['top']

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

    return pixels.raw
