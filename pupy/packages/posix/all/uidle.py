# -*- encoding: utf-8 -*-

import ctypes
import os
import time

from display import attach_to_display
from ctypes.util import find_library

import psutil

class XScreenSaverInfo(ctypes.Structure):
    _fields_ = [
        ('window',      ctypes.c_ulong), # screen saver window
        ('state',       ctypes.c_int),   # off,on,disabled
        ('kind',        ctypes.c_int),   # blanked,internal,external
        ('since',       ctypes.c_ulong), # milliseconds
        ('idle',        ctypes.c_ulong), # milliseconds
        ('event_mask',  ctypes.c_ulong)] # events

xlib = None
xss = None
xlibs_available = None

XOpenDisplay = None
XDefaultRootWindow = None
XCloseDisplay = None
XFree = None
XScreenSaverAllocInfo = None
XScreenSaverQueryInfo = None

def load_uidle_libs():
    global xlib, xss
    global XOpenDisplay, XDefaultRootWindow, XCloseDisplay
    global XFree, XScreenSaverAllocInfo, XScreenSaverQueryInfo
    global xlibs_available

    if xlibs_available is not None:
        return

    try:
        xlib = ctypes.cdll.LoadLibrary(find_library('X11'))

        XOpenDisplay = xlib.XOpenDisplay
        XOpenDisplay.argtypes = [ctypes.c_char_p]
        XOpenDisplay.restype = ctypes.c_void_p

        XDefaultRootWindow = xlib.XDefaultRootWindow
        XDefaultRootWindow.argtypes = [ctypes.c_void_p]
        XDefaultRootWindow.restype = ctypes.c_ulong

        XCloseDisplay = xlib.XCloseDisplay
        XCloseDisplay.argtypes = [ctypes.c_void_p]
        XCloseDisplay.restype = ctypes.c_int

        XFree = xlib.XFree
        XFree.argtypes = [ctypes.c_void_p]
        XFree.restype = ctypes.c_int

    except:
        xlib = None

    try:
        xss = ctypes.cdll.LoadLibrary('libXss.so.1')

        XScreenSaverAllocInfo = xss.XScreenSaverAllocInfo
        XScreenSaverAllocInfo.restype = ctypes.POINTER(XScreenSaverInfo)

        XScreenSaverQueryInfo = xss.XScreenSaverQueryInfo
        XScreenSaverQueryInfo.argtypes = [
            ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p
        ]
        XScreenSaverQueryInfo.restype.restype = ctypes.c_int

    except:
        xss = None

    if xlib and xss:
        xlibs_available = True

def get_gui_idle(display=None):
    if not os.environ.get('DISPLAY'):
        if display:
            if not attach_to_display(display):
                return None
        else:
            return None

    load_uidle_libs()

    if xlibs_available is False:
        return None

    display = XOpenDisplay(os.environ.get('DISPLAY'))
    if not display:
        return None

    xssinfo = XScreenSaverAllocInfo()
    if not xssinfo:
        XCloseDisplay(display)
        return None

    idle = None

    status = XScreenSaverQueryInfo(display, XDefaultRootWindow(display), xssinfo)
    if status:
        idle = xssinfo.contents.idle
        XFree(xssinfo)

    XCloseDisplay(display)

    return int(idle / 1000) if idle else None

def get_cli_idle():
    now = time.time()

    idles = []
    for user in psutil.users():
        if not user.terminal:
            continue

        try:
            dev_stat = os.stat('/dev/' + user.terminal)
        except OSError:
            continue

        idles.append(now - dev_stat.st_atime)

    if not idles:
        return None

    idle = min(idles)
    psutil._pmap = {}
    return idle

def get_idle():
    cli_idle = get_cli_idle()

    try:
        gui_idle = get_gui_idle()
    except:
        gui_idle = None

    if gui_idle is None:
        return cli_idle
    elif cli_idle is None:
        return gui_idle
    else:
        return min(cli_idle, gui_idle)
