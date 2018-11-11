#!/usr/bin/env python
# -*- coding: utf-8 -*-

import random
import os
import struct
import platform
import re

import fcntl
import termios

from pygments import highlight

TERM = os.environ.get('TERM')
if TERM and TERM.endswith('256color'):
    from pygments.formatters import Terminal256Formatter as TerminalFormatter
else:
    from pygments.formatters import TerminalFormatter

from pupylib.PupyOutput import (
    Hint, Text, NewLine, Title, MultiPart, Indent, Color,
    TruncateToTerm, Error, Log, Warn, Success, Info,
    ServiceInfo, Section, Line, List, Table, Pygment
)

PYGMENTS_STYLE='native'

ESC_REGEX = re.compile(r'(\033[^m]+m)')

COLORS = {
    'blue': '\033[34m',
    'lightblue': '\033[34;1m',
    'red': '\033[31m',
    'lightred': '\033[31;1m',
    'green': '\033[32m',
    'lightgreen': '\033[32;1m',
    'yellow': '\033[33m',
    'lightyellow': '\033[1;33m',
    'magenta': '\033[35m',
    'lightmagenta': '\033[1;35m',
    'cyan': '\033[36m',
    'grey': '\033[37m',
    'darkgrey': '\033[1;30m',
    'white': '\033[39m'
}

SHADOW_SCREEN_TO = '\033[?1049h\033[2J\033[1;1H'
SHADOW_SCREEN_FROM = '\033[?1049l'
RESET = '\033g\033c\033r\033m'

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

def colorize(text, color, prompt=False):
    if not text:
        return ''
    elif color == 'white':
        return text

    ttype = type(text)
    if ttype not in (str, unicode):
        text = str(text)

    if color.lower() == 'random':
        color = random.choice(COLORS.keys())

    ccode = COLORS.get(color.lower())
    if prompt:
        ccode = '\001' + ccode + '\002'

    sequence = [ccode, text]

    eccode = '\033[0m'

    if prompt:
        eccode = '\001' + eccode + '\002'

    sequence.append(eccode)


    if ccode:
        joiner = u'' if ttype == unicode else ''
        return joiner.join(sequence)

    return text

def terminal_size():
    h, w, hp, wp = struct.unpack('HHHH',
        fcntl.ioctl(0, termios.TIOCGWINSZ,
        struct.pack('HHHH', 0, 0, 0, 0)))
    return w, h


def ediff(s):
    utf8diff = 0

    if type(s) is str:
        s2 = s.decode('utf8', errors='replace')
        utf8diff = len(s) - len(s2)

    return utf8diff + len(''.join(ESC_REGEX.findall(s)))

def elen(s):
    return len(s) - ediff(s)

def ejust(line, width):
    initial = line
    while elen(line) > width:
        line = line[:width+ediff(line)]

    removed = len(initial) - len(line)
    try:
        ccindex = initial.rindex('\033[0m')
        if ccindex >= removed - 4:
            if ccindex > len(line):
                line = line[:ccindex]

            line += '\033[0m'

    except ValueError:
        pass

    return line

def obj2utf8(obj):
    objtype = type(obj)

    if issubclass(objtype, Hint):
        pass

    elif objtype == dict:
        for k in obj:
            obj[k] = obj2utf8(obj[k])

    elif objtype == list:
        for i in range(0, len(obj)):
            obj[i] = obj2utf8(obj[i])

    elif objtype == tuple:
        obj = list(obj)
        for i in range(0, len(obj)):
            obj[i] = obj2utf8(obj[i])

        obj = tuple(obj)

    elif objtype == unicode:
        pass

    elif objtype == str:
        obj = obj.decode('utf-8', errors='replace')

    else:
        obj = unicode(obj)

    return obj

def get_columns_size(columns):
    size_dic = {}
    for column in columns:
        for key, value in column.iteritems():
            value_elen = elen(value)
            if key not in size_dic or size_dic[key] < value_elen:
                size_dic[key] = value_elen

    return size_dic

def table_format(diclist, wl=[], bl=[], truncate=None, legend=True):
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
        (
            x if type(x) in (tuple, list) else (x, x)
        ) for x in (wl if wl else diclist[0].iterkeys()) if x not in bl
    ]

    titlesdic = {}
    for key,title in keys:
        titlesdic[key] = title

    if legend:
        diclist.insert(0, titlesdic)

    colsize = get_columns_size(diclist)
    i = 0

    for c in diclist:
        if i == 1 and legend:
            res.append(
                u'-'*sum([
                    k+2 for k in [y for x,y in colsize.iteritems() if x in titlesdic
                ]]))
        i += 1

        lines = []
        for key,_ in keys:
            value = c.get(key, '').strip()
            lines.append(value.ljust(colsize[key]+2 + ediff(value)))

        res.append(u''.join(lines))

    return '\n'.join(res)

def hint_to_text(text, width=0):
    if text is None:
        return ''

    hint = type(text)

    if issubclass(hint, Hint) and not issubclass(hint, Text):
        raise ValueError('hint_to_text() support only Text messages')
    elif issubclass(hint, Text):
        pass
    elif hint == str:
        try:
            return text.decode('utf-8')
        except UnicodeDecodeError:
            return text.decode('latin1')
    elif hint == unicode:
        return text.encode('utf-8')
    else:
        return obj2utf8(text)

    if hint == NewLine:
        return '\n'*int(text.data)
    elif hint == Title:
        if width <= 0:
            real_width, _ = terminal_size()
            width = real_width + width

        title = hint_to_text(text.data)
        tlen = elen(title)
        ajust = width - tlen - 4
        ljust = 0
        rjust = 0
        if ajust > 0:
            ljust = ajust/2
            rjust = ajust - ljust

        title = '>>' + (' '*ljust) + title + (' '*rjust) + '<<'
        title = ('-'*width) + '\n' + title + '\n' + ('-'*width)

        return colorize(title, 'lightyellow')
    elif hint == MultiPart:
        return '\n\n'.join(
            hint_to_text(x, width) for x in text.data
        )
    elif hint == Indent:
        return '\n'.join(
            (' '*text.indent) + x for x in hint_to_text(
                text.data, width).split('\n')
        )

    elif hint == Color:
        return colorize(hint_to_text(text.data, width), text.color)
    elif hint == TruncateToTerm:
        if width <= 0:
            real_width, _ = terminal_size()
            width = real_width + width

        text = hint_to_text(text.data, width)
        if text == str:
            text = text.decode('utf-8', errors='replace')

        return '\n'.join(ejust(x, width) for x in text.split('\n'))
    elif hint == Error:
        header = text.header
        text = text.data
        etype = type(text)
        if issubclass(etype, Exception) and etype.__class__.__name__ != 'type':
            text = '({}) {}'.format(type(text).__class__.__name__, text)
        else:
            text = hint_to_text(text, width).rstrip()

        if header:
            text = '{}: {}'.format(colorize(header, 'yellow'), text)

        return colorize('[-] ','red')+text
    elif hint == Log:
        return hint_to_text(text.data, width).rstrip()
    elif hint == Warn:
        return colorize('[!] ','yellow')+hint_to_text(text.data, width).rstrip()
    elif hint == Success:
        return colorize('[+] ','green')+hint_to_text(text.data, width).rstrip()
    elif hint == Info:
        return colorize('[%] ','grey')+hint_to_text(text.data, width).rstrip()
    elif hint == ServiceInfo:
        return ''.join([
            colorize('[*] ','blue'),
            hint_to_text(text.data, width).rstrip()
        ])
    elif hint == Section:
        return '\n'.join([
            colorize('#>#>  ','green') + hint_to_text(text.header, width)+ colorize('  <#<#','green'),
            hint_to_text(text.data, width)
        ])
    elif hint == Line:
        return text.dm.join(hint_to_text(v, width) for v in text.data)
    elif hint == List:
        return (hint_to_text(text.caption, width) + '\n' if text.caption else '') + (
            '\n'.join([
                (
                    (' '*text.indent) + (
                        (hint_to_text(text.bullet, width) + ' ') if text.bullet else ''
                    ) + hint_to_text(x, width)
                ) for x in text.data
            ])
        )
    elif hint == Table:
        table_data = [
            {
                k:hint_to_text(v, width) for k,v in record.iteritems()
            } for record in text.data
        ]

        return (
            '\n'*text.vspace + '{ ' + hint_to_text(text.caption, width) + ' }\n' if text.caption else ''
        ) + table_format(table_data, wl=text.headers, legend=text.legend) + '\n'*text.vspace

    elif hint == Pygment:
        lexer = text.lexer
        text = hint_to_text(text.data, width)
        return highlight(text, lexer, TerminalFormatter(style=PYGMENTS_STYLE))

    else:
        raise NotImplementedError('hint_to_text not implemented for {}'.format(
            hint.__class__.__name__))
