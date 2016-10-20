#!/usr/bin/env python
# -*- coding: utf-8 -*-

import random
import os
import struct
import platform

# https://gist.githubusercontent.com/jtriley/1108174/raw/6ec4c846427120aa342912956c7f717b586f1ddb/terminalsize.py
def consize():
    """ getTerminalSize()
     - get width and height of console
     originally retrieved from:
     http://stackoverflow.com/questions/566746/how-to-get-console-window-width-in-python
    """
    current_os = platform.system()
    tuple_xy = None
    if current_os == 'Windows':
        tuple_xy = _size_windows()

    if current_os in ['Linux', 'Darwin'] or current_os.startswith('CYGWIN'):
        tuple_xy = _size_linux()

    return tuple_xy or (None, None)

def _size_windows():
    try:
        from ctypes import windll, create_string_buffer
        h = windll.kernel32.GetStdHandle(-12)
        csbi = create_string_buffer(22)
        res = windll.kernel32.GetConsoleScreenBufferInfo(h, csbi)
        if res:
            (bufx, bufy, curx, cury, wattr,
             left, top, right, bottom,
             maxx, maxy) = struct.unpack("hhhhHhhhhhh", csbi.raw)
            sizex = right - left + 1
            sizey = bottom - top + 1
            return sizex, sizey
    except:
        pass

def _size_linux():
    def ioctl_GWINSZ(fd):
        try:
            import fcntl
            import termios
            cr = struct.unpack(
                'hh',
                fcntl.ioctl(fd, termios.TIOCGWINSZ, '1234'))
            return cr
        except:
            pass

    cr = ioctl_GWINSZ(0) or ioctl_GWINSZ(1) or ioctl_GWINSZ(2)
    if not cr:
        try:
            fd = os.open(os.ctermid(), os.O_RDONLY)
            cr = ioctl_GWINSZ(fd)
            os.close(fd)
        except:
            pass

    if not cr:
        try:
            cr = (os.environ['LINES'], os.environ['COLUMNS'])
        except:
            return None

    return int(cr[1]), int(cr[0])

def colorize(s, color):
    if s is None:
        return ""
    s=str(s)
    res=s
    COLOR_STOP="\033[0m"
    if color.lower()=="random":
        color=random.choice(["blue","red","green","yellow"])
    if color.lower()=="blue":
        res="\033[34m"+s+COLOR_STOP
    if color.lower()=="red":
        res="\033[31m"+s+COLOR_STOP
    if color.lower()=="green":
        res="\033[32m"+s+COLOR_STOP
    if color.lower()=="yellow":
        res="\033[33m"+s+COLOR_STOP
    if color.lower()=="grey":
        res="\033[37m"+s+COLOR_STOP
    if color.lower()=="darkgrey":
        res="\033[1;30m"+s+COLOR_STOP
    return res

def terminal_size():
    import fcntl, termios, struct
    h, w, hp, wp = struct.unpack('HHHH',
        fcntl.ioctl(0, termios.TIOCGWINSZ,
        struct.pack('HHHH', 0, 0, 0, 0)))
    return w, h
