# -*- coding: utf-8 -*-

import os
import psutil
import ctypes
import pupyps
import pwd
import socket

from ctypes.util import find_library

xlibs_available = None
x11 = None
xau = None

def load_display_libs():
    global xlibs_available
    global x11, xau

    if xlibs_available is not None:
        return

    try:
        x11 = ctypes.cdll.LoadLibrary(find_library('X11'))
        x11.XOpenDisplay.restype = ctypes.c_void_p
        x11.XOpenDisplay.argtypes = [ctypes.c_char_p]
        x11.XCloseDisplay.argtypes = [ctypes.c_void_p]
    except:
        x11 = None
        pass

    try:
        xau = ctypes.cdll.LoadLibrary(find_library('Xau'))
        xau.XauGetAuthByAddr.restype = ctypes.POINTER(XAuth)
        xau.XauGetAuthByAddr.argtypes = [
            ctypes.c_ushort,
            ctypes.c_ushort, ctypes.c_char_p,
            ctypes.c_ushort, ctypes.c_char_p,
            ctypes.c_ushort, ctypes.c_char_p
       ]
        xau.XauDisposeAuth.argtypes = [ctypes.POINTER(XAuth)]
    except:
        xau = None
        pass

    xlibs_available = x11 and xau

class XAuth(ctypes.Structure):
    _fields_ = [
        ('family',         ctypes.c_ushort),
        ('address_length', ctypes.c_ushort),
        ('address',        ctypes.c_char_p),
        ('number_length',  ctypes.c_ushort),
        ('number',         ctypes.c_char_p),
        ('name_length',    ctypes.c_ushort),
        ('name',           ctypes.c_char_p),
        ('data_length',    ctypes.c_ushort),
        ('data',           ctypes.c_char_p)
   ]

Families = {
    0: 'tcp',
    6: 'tcp6',
    256: 'unix',
}

def check_display(name, authority):
    global x11

    load_display_libs()

    if not x11 or not name or not authority:
        return False

    try:
        open(authority).close()
    except:
        return False

    XAUTHORITY_OLD = os.environ.get('XAUTHORITY')
    DISPLAY_OLD = os.environ.get('DISPLAY')

    os.environ['XAUTHORITY'] = authority
    os.environ['DISPLAY'] = name

    display = x11.XOpenDisplay(name)
    result = bool(display)
    if display:
        x11.XCloseDisplay(display)

    if XAUTHORITY_OLD:
        os.environ['XAUTHORITY'] = XAUTHORITY_OLD
    else:
        del os.environ['XAUTHORITY']

    if DISPLAY_OLD:
        os.environ['DISPLAY'] = DISPLAY_OLD
    else:
        del os.environ['DISPLAY']

    return result

def guess_displays():
    displays = {}
    userinfos = {}

    load_display_libs()

    for process in psutil.process_iter():
        try:
            info = process.as_dict(['username', 'environ'])
        except:
            continue

        if info['username'] and info['environ']:
            if 'DISPLAY' not in info['environ']:
                continue

            try:
                if not info['username'] in userinfos:
                    userinfos[info['username']] = pwd.getpwnam(info['username'])
            except:
                continue

            DISPLAY = info['environ'].get('DISPLAY')
            XAUTHORITY = info['environ'].get('XAUTHORITY')

            if DISPLAY not in displays:
                displays[DISPLAY] = set()

            if not XAUTHORITY:
                XAUTHORITY = os.path.join(
                    userinfos[info['username']].pw_dir, '.Xauthority'
               )

            pair = (info['username'], XAUTHORITY)
            if pair not in displays[DISPLAY] and check_display(DISPLAY, XAUTHORITY):
                displays[DISPLAY].add(pair)

    for user, hosts in pupyps.users().iteritems():
        for host, terminals in hosts.iteritems():
            for terminal in terminals:
                try:
                    executable = os.path.basename(
                        os.path.realpath(terminal['exe'])
                   )

                    if executable not in ('X', 'Xorg'):
                        continue

                    DISPLAY = None
                    XAuthority = None
                    NextIsXAuthority = False

                    for arg in terminal['cmdline']:
                        if arg.startswith(':'):
                            DISPLAY = arg
                        elif arg == '-auth':
                            NextIsXAuthority = True
                        elif NextIsXAuthority:
                            XAuthority = arg
                            NextIsXAuthority = False

                    if not DISPLAY:
                        continue

                    pair = (user, XAuthority)
                    if DISPLAY not in displays:
                        displays[DISPLAY] = set()

                    if pair not in displays[DISPLAY] and check_display(DISPLAY, XAuthority):
                        displays[DISPLAY].add(pair)

                except:
                    pass

    return {
        k:list(v) for k,v in displays.iteritems()
    }

def attach_to_display(name, xauth=None):
    load_display_libs()

    if not xauth:
        displays = guess_displays()
        if name not in displays:
            return False

        for user, xauth in displays[name]:
            os.environ['DISPLAY'] = name
            os.environ['XAUTHORITY'] = xauth
            return True
    else:
        if check_display(name, xauth):
            os.environ['DISPLAY'] = name
            os.environ['XAUTHORITY'] = xauth
            return True

    return False

def extract_xauth_info(name, authtype='MIT-MAGIC-COOKIE-1'):

    load_display_libs()

    global xau, Families
    if not xau or not name:
        return None

    hostname = socket.gethostname()

    if not hostname or not name.startswith(':'):
        return None

    name = name[1:]

    xauth = xau.XauGetAuthByAddr(
        256,
        len(hostname), hostname,
        len(name), name,
        len(authtype), authtype
    )

    if not xauth:
        return None

    result = (
        Families[xauth.contents.family],
        xauth.contents.address[:xauth.contents.address_length],
        xauth.contents.number[:xauth.contents.number_length],
        xauth.contents.name[:xauth.contents.name_length],
        xauth.contents.data[:xauth.contents.data_length].encode('hex')
    )

    xau.XauDisposeAuth(xauth)

    return result

def when_attached(callback, name=':0', poll=10):
    import threading
    import time

    load_display_libs()

    def _waiter():
        while not attach_to_display(name):
            time.sleep(poll)

        callback()

    waiter = threading.Thread(target=_waiter)
    waiter.daemon = True
    waiter.start()
