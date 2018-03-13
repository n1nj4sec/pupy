#!/usr/bin/env python
# -*- coding: utf-8 -*-

import random
import os
import struct
import platform
import re

from pupylib.PupyOutput import *

ESC_REGEX = re.compile('(\033[^m]+m)')

# https://gist.githubusercontent.com/jtriley/1108174/raw/6ec4c846427120aa342912956c7f717b586f1ddb/terminalsize.py
def consize(file=None):
    """ getTerminalSize()
     - get width and height of console
     originally retrieved from:
     http://stackoverflow.com/questions/566746/how-to-get-console-window-width-in-python
    """
    current_os = platform.system()
    tuple_xy = None
    if current_os == 'Windows':
        tuple_xy = _size_windows(file)

    if current_os in ['Linux', 'Darwin'] or current_os.startswith('CYGWIN'):
        tuple_xy = _size_linux(file)

    return tuple_xy or (None, None)

def _size_windows(file=None):
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

def _size_linux(file=None):
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

    if file:
        cr = ioctl_GWINSZ(file.fileno())
    else:
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

    if type(s) not in (str, unicode):
        s = str(s)

    res=s
    COLOR_STOP="\033[0m"
    if color.lower()=="random":
        color=random.choice(["blue","red","green","yellow"])

    if color.lower()=="blue":
        res="\033[34m"+s+COLOR_STOP
    elif color.lower()=="red":
        res="\033[31m"+s+COLOR_STOP
    elif color.lower()=="lightred":
        res="\033[31;1m"+s+COLOR_STOP
    elif color.lower()=="green":
        res="\033[32m"+s+COLOR_STOP
    elif color.lower()=="lightgreen":
        res="\033[32;1m"+s+COLOR_STOP
    elif color.lower()=="yellow":
        res="\033[33m"+s+COLOR_STOP
    elif color.lower()=="lightyellow":
        res="\033[1;33m"+s+COLOR_STOP
    elif color.lower()=="magenta":
        res="\033[35m"+s+COLOR_STOP
    elif color.lower()=="cyan":
        res="\033[36m"+s+COLOR_STOP
    elif color.lower()=="grey":
        res="\033[37m"+s+COLOR_STOP
    elif color.lower()=="darkgrey":
        res="\033[1;30m"+s+COLOR_STOP

    return res

def terminal_size():
    import fcntl, termios, struct
    h, w, hp, wp = struct.unpack('HHHH',
        fcntl.ioctl(0, termios.TIOCGWINSZ,
        struct.pack('HHHH', 0, 0, 0, 0)))
    return w, h

def color(s, color, prompt=False, colors_enabled=True):
    """ color a string using ansi escape characters. set prompt to true to add marks for readline to see invisible portions of the prompt
    cf. http://stackoverflow.com/questions/9468435/look-how-to-fix-column-calculation-in-python-readline-if-use-color-prompt"""
    if s is None:
        return ""

    if not colors_enabled:
        return s

    res=s
    COLOR_STOP="\033[0m"
    prompt_stop=""
    prompt_start=""
    if prompt:
        prompt_stop="\002"
        prompt_start="\001"
    if prompt:
        COLOR_STOP=prompt_start+COLOR_STOP+prompt_stop
    if color.lower()=="random":
        color=random.choice(["blue","red","green","yellow"])
    if color.lower()=="blue":
        res=prompt_start+"\033[34m"+prompt_stop+s+COLOR_STOP
    if color.lower()=="red":
        res=prompt_start+"\033[31m"+prompt_stop+s+COLOR_STOP
    if color.lower()=="green":
        res=prompt_start+"\033[32m"+prompt_stop+s+COLOR_STOP
    if color.lower()=="yellow":
        res=prompt_start+"\033[33m"+prompt_stop+s+COLOR_STOP
    if color.lower()=="grey":
        res=prompt_start+"\033[37m"+prompt_stop+s+COLOR_STOP
    if color.lower()=="darkgrey":
        res=prompt_start+"\033[1;30m"+prompt_stop+s+COLOR_STOP
    return res

def ediff(s):
    utf8diff = 0

    if type(s) is str:
        s2 = s.decode('utf8', errors='replace')
        utf8diff = len(s) - len(s2)

    return utf8diff + len(''.join(ESC_REGEX.findall(s)))

def elen(s):
    print "t: {}".format(repr(s))
    return len(s) - ediff(s)

def obj2utf8(obj):
    if type(obj) == dict:
        for k in obj:
            obj[k] = obj2utf8(obj[k])

    elif type(obj) == list:
        for i in range(0, len(obj)):
            obj[i] = obj2utf8(obj[i])

    elif type(obj) == tuple:
        obj = list(obj)
        for i in range(0, len(obj)):
            obj[i] = obj2utf8(obj[i])

        obj = tuple(obj)

    elif type(obj) == unicode:
        pass

    elif type(obj) == str:
        obj = obj.decode('utf-8', errors='replace')

    else:
        obj = unicode(obj)

    return obj

def get_columns_size(l):
    size_dic = {}
    for d in l:
        for i,k in d.iteritems():
            l = elen(k)
            if not i in size_dic or size_dic[i] < l:
                size_dic[i] = l

    return size_dic

def table_format(diclist, wl=[], bl=[], truncate=None):
    """
        this function takes a list a dictionaries to display in columns. Dictionnaries keys are the columns names.
        All dictionaries must have the same keys.
        wl is a whitelist of column names to display
        bl is a blacklist of columns names to hide
    """
    res = []

    if not diclist:
        return u''

    diclist = obj2utf8(diclist)
    keys = [
        x for x in ( wl if wl else diclist[0].iterkeys() ) if not x in bl
    ]

    titlesdic = {}
    for k in keys:
        titlesdic[k] = k

    diclist.insert(0, titlesdic)
    colsize = get_columns_size(diclist)
    i = 0

    for c in diclist:
        if i == 1:
            res.append(
                u'-'*sum([
                    k+2 for k in [y for x,y in colsize.iteritems() if x in titlesdic
                ]]))
        i += 1

        lines = []
        for name in keys:
            value = c[name].strip()
            lines.append(value.ljust(colsize[name]+2 + ediff(value)))

        res.append(u''.join(lines))

    return u'\n'.join(res)

def hint_to_text(text, width=0):
    if text is None:
        return ''

    hint = type(text)

    if issubclass(hint, Hint) and not issubclass(hint, Text):
        raise ValueError('hint_to_text() support only Text messages')
    elif issubclass(hint, Text):
        pass
    elif hint in (str, unicode):
        return text
    else:
        return obj2utf8(text)

    if hint == NewLine:
        return '\n'*int(text.data)
    elif hint == MultiPart:
        return '\n\n'.join(
            hint_to_text(x, width) for x in text.data
        )
    elif hint == Color:
        return color(hint_to_text(text.data, width), text.color)
    elif hint == TruncateToTerm:
        if width <= 0:
            real_width, _ = terminal_size()
            width = real_width + width

        text = hint_to_text(text.data, width)
        return '\n'.join(x[:width+ediff(x)] for x in text.split('\n'))
    elif hint == Error:
        return color('[-] ','red')+hint_to_text(text.data, width).rstrip()
    elif hint == Log:
        return hint_to_text(text.data, width).rstrip()
    elif hint == Warning:
        return color('[!] ','yellow')+hint_to_text(text.data, width).rstrip()
    elif hint == Success:
        return color('[+] ','green')+hint_to_text(text.data, width).rstrip()
    elif hint == Info:
        return color('[%] ','grey')+hint_to_text(text.data, width).rstrip()
    elif hint == ServiceInfo:
        return ''.join([
            color('[*] ','blue'),
            hint_to_text(text.data, width).rstrip()
        ])
    elif hint == Section:
        return '\n'.join([
            color('#>#>  ','green') + hint_to_text(text.data, width)+ color('  <#<#','green'),
            hint_to_text(text.payload, width)
        ])
    elif hint == Table:
        table_data = [
            {
                k:hint_to_text(v, width) for k,v in record.iteritems()
            } for record in text.data
        ]

        return (
            '{ ' + hint_to_text(text.caption.upper(), width) + ' }\n' if text.caption else ''
        ) + table_format(table_data, wl=text.headers)

    else:
        raise NotImplementedError('hint_to_text not implemented for {}'.format(
            hint.__class__.__name__))
