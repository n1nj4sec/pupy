#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import sys
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

DEFAULT_MULTIBYTE_CP = 'utf-8'
FALLBACK_MULTIBYTE_CP = 'latin-1'


if sys.version_info.major > 2:
    import _io

    class AnyIOWrapper(object):
        __slots__ = ('fileobj')

        def __init__(self, pyfile):
            self.fileobj = os.fdopen(
                pyfile.fileno(), 'ab', 0
            )

        def fileno(self):
            return self.fileobj.fileno()

        def write(self, data):
            if isinstance(data, bytes):
                return self.fileobj.write(data)
            elif isinstance(data, str):
                return self.fileobj.write(
                    data.encode(DEFAULT_MULTIBYTE_CP)
                )

            return 0

        def flush(self):
            pass

    def fix_stdout(stdout):
        if isinstance(stdout, _io.TextIOWrapper):
            return AnyIOWrapper(stdout)

        return stdout

    xrange = range
    unicode = str

else:
    def fix_stdout(stdout):
        return stdout


def from_bytes(value, errors=None):
    if errors is not None:
        return value.decode(DEFAULT_MULTIBYTE_CP, errors=errors)
    else:
        try:
            return value.decode(DEFAULT_MULTIBYTE_CP)
        except UnicodeError:
            return value.decode(FALLBACK_MULTIBYTE_CP)


def to_bytes(value):
    if isinstance(value, bytes):
        return value

    elif isinstance(value, unicode):
        return value.encode(DEFAULT_MULTIBYTE_CP)

    else:
        return unicode(value).encode(DEFAULT_MULTIBYTE_CP)


PYGMENTS_STYLE = 'native'

ESC_REGEX = re.compile(
    br'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])'
)

COLORS = {
    'blue': b'\033[34m',
    'lightblue': b'\033[34;1m',
    'red': b'\033[31m',
    'lightred': b'\033[31;1m',
    'green': b'\033[32m',
    'lightgreen': b'\033[32;1m',
    'yellow': b'\033[33m',
    'lightyellow': b'\033[1;33m',
    'magenta': b'\033[35m',
    'lightmagenta': b'\033[1;35m',
    'cyan': b'\033[36m',
    'grey': b'\033[37m',
    'darkgrey': b'\033[1;30m',
    'white': b'\033[39m',
}

NO_COLOR = b'\033[0m'

SHADOW_SCREEN_TO = b'\033[?1049h\033[2J\033[1;1H'
SHADOW_SCREEN_FROM = b'\033[?1049l'

RESET = b'\033g\033c\033r\033m'

CUR_LEFT = b'\033[0G'
CUR_UP = b'\033[A'
CUR_DOWN = b'\033[E'
CUR_RIGHT = b'\033[C'
DEL_RIGHT = b'\033[0K'
DEL_ALL = b'\033[2K'

STOR_CUR = b'\033[s'
LOAD_CUR = b'\033[u'


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
    to_str = False
    color = color.lower()

    if not isinstance(text, bytes):
        to_str = True

        text = text.encode(DEFAULT_MULTIBYTE_CP)

    if color == 'random':
        color = random.choice(COLORS)

    ccode = COLORS.get(color)

    if ccode:
        ncode = NO_COLOR

        if prompt:
            ccode = b'\001' + ccode + b'\002'
            ncode = b'\001' + ncode + b'\002'

        text = b''.join([ccode, text, ncode])

    if to_str:
        text = text.decode(DEFAULT_MULTIBYTE_CP)

    return text


def terminal_size():
    h, w, hp, wp = struct.unpack(
        'HHHH',
        fcntl.ioctl(
            0, termios.TIOCGWINSZ,
            struct.pack('HHHH', 0, 0, 0, 0)
        )
    )

    return w, h


def remove_esc(s, coding=DEFAULT_MULTIBYTE_CP):
    encode = False

    if not isinstance(s, bytes):
        encode = True
        s = s.decode(DEFAULT_MULTIBYTE_CP)

    s = ESC_REGEX.sub(b'', s)

    if encode:
        s = s.encode(DEFAULT_MULTIBYTE_CP)

    return s


def non_symbol_len(s, coding=DEFAULT_MULTIBYTE_CP):
    if isinstance(s, bytes):
        total_len = len(s.decode(coding))
    else:
        total_len = len(s)
        s = s.encode(coding)

    return total_len - len(
        ESC_REGEX.sub(b'', s).decode(coding, 'ignore')
    )


def symbol_len(s, coding=DEFAULT_MULTIBYTE_CP):
    if not s:
        return 0

    if not isinstance(s, bytes):
        s = s.encode(coding)

    return len(
        ESC_REGEX.sub(b'', s).decode(coding, 'ignore')
    )


def symbol_trunc(s, width, coding=DEFAULT_MULTIBYTE_CP):
    if not s:
        return s

    if not isinstance(s, bytes):
        s = s.encode(DEFAULT_MULTIBYTE_CP)

    pos = 0
    last_ascii_esc_end = 0

    result = b''

    in_escape_code = False

    while True:
        next_escape_code = ESC_REGEX.search(s, pos=pos)

        if not next_escape_code:
            # Rest of line is free of escape codes
            # Decode it as unicode, cut necessary bytes
            # Then encode back and put to result

            result += s[pos:].decode(coding)[:width].encode(coding)
            break

        first_pos, last_pos = next_escape_code.span(0)

        symbols_len = 0

        if first_pos > pos:
            # Consume non-escape part (or continuation)
            first_symbols = s[pos:first_pos].decode(coding)
            symbols_len = len(first_symbols)

            if symbols_len >= width:
                # Consume and stop
                result += first_symbols[:width].encode(coding)
                break

        # We are either starting from escape sequence
        # or need to consume it

        result += s[pos:last_pos]

        in_escape_code = True
        pos = last_pos
        width -= symbols_len

        last_ascii_esc_end = last_pos

    if in_escape_code:
        # Likely we need to close current escape code
        # Let's just find the last one and attach it

        last_match = None

        for match in ESC_REGEX.finditer(s, last_ascii_esc_end):
            last_match = match

        if last_match:
            first_pos, last_pos = last_match.span(0)
            result += s[first_pos:last_pos]

    return result


def deep_as_bytes(obj):
    objtype = type(obj)

    if objtype is bytes:
        return obj

    elif issubclass(objtype, Hint):
        pass

    elif issubclass(objtype, dict):
        for k in obj:
            obj[k] = deep_as_bytes(obj[k])

    elif issubclass(objtype, list):
        for i, item in enumerate(obj):
            obj[i] = deep_as_bytes(item)

    elif issubclass(objtype, tuple):
        obj = [None] * len(tuple)
        for i, item in enumerate(obj):
            obj[i] = deep_as_bytes(item)

        obj = objtype(obj)

    else:
        obj = to_bytes(obj)

    return obj


def get_columns_size(columns):
    size_dic = {}

    for column in columns:
        for key, value in column.items():
            value_elen = symbol_len(value)
            if key not in size_dic or size_dic[key] < value_elen:
                size_dic[key] = value_elen

    return size_dic


def table_as_bytes(diclist, wl=[], bl=[], truncate=None, legend=True):
    """
    this function takes a list a dictionaries to display in columns.
    Dictionnaries keys are the columns names.
    All dictionaries must have the same keys.
    wl is a whitelist of column names to display
    bl is a blacklist of columns names to hide
    """
    res = []

    if not diclist:
        return b''

    diclist = deep_as_bytes(diclist)

    keys = [
        (
            x if isinstance(x, (tuple, list)) else (x, x)
        ) for x in (wl if wl else diclist[0]) if x not in bl
    ]

    titlesdic = {}
    for key, title in keys:
        titlesdic[key] = title

    if legend:
        diclist.insert(0, titlesdic)

    colsize = get_columns_size(diclist)
    i = 0

    for c in diclist:
        if i == 1 and legend:
            res.append(
                b'-'*sum([
                    k+2 for k in [
                        y for x, y in colsize.items() if x in titlesdic
                    ]
                ])
            )
        i += 1

        lines = []
        for key, _ in keys:
            value = deep_as_bytes(c.get(key, '').strip())
            lines.append(value.ljust(colsize[key]+2 + non_symbol_len(value)))

        res.append(b''.join(lines))

    return b'\n'.join(res)


def as_term_bytes(text, width=0):
    if text is None:
        return ''

    hint = type(text)

    if issubclass(hint, Hint) and not issubclass(hint, Text):
        raise ValueError('as_term_bytes() support only Text messages')
    elif issubclass(hint, Text):
        pass
    elif hint is bytes:
        return text
    elif hint is unicode:
        return to_bytes(text)
    else:
        return deep_as_bytes(text)

    if hint is NewLine:
        return b'\n' * int(text.data)

    elif hint is Title:
        if width <= 0:
            real_width, _ = terminal_size()
            width = real_width + width

        title = as_term_bytes(text.data, width)
        tlen = symbol_len(title)
        ajust = width - tlen - 4
        ljust = 0
        rjust = 0

        if ajust > 0:
            ljust = ajust // 2
            rjust = ajust - ljust

        title = b'>>' + (b' '*ljust) + title + (b' '*rjust) + b'<<'
        title = (b'-'*width) + b'\n' + title + b'\n' + (b'-'*width)

        return colorize(title, 'lightyellow')

    elif hint is MultiPart:
        return b'\n\n'.join(
            as_term_bytes(x, width) for x in text.data
        )

    elif hint is Indent:
        return b'\n'.join(
            (b' '*text.indent) + x for x in as_term_bytes(
                text.data, width).split(b'\n')
        )

    elif hint is Color:
        return colorize(
            as_term_bytes(text.data, width), text.color
        )

    elif hint is TruncateToTerm:
        if width <= 0:
            real_width, _ = terminal_size()
            width = real_width + width

        text = as_term_bytes(text.data, width)
        return b'\n'.join(
            symbol_trunc(x, width) for x in text.split(b'\n')
        )

    elif hint is Error:
        header = text.header
        text = text.data
        etype = type(text)

        if issubclass(etype, Exception) and etype.__class__.__name__ != 'type':
            text = '({}) {}'.format(type(text).__class__.__name__, text)

        text = as_term_bytes(text, width).rstrip()
        if header:
            header = as_term_bytes(header, width)
            text = colorize(header, 'yellow') + b': ' + text

        return colorize(b'[-] ', 'red') + text

    elif hint is Log:
        return as_term_bytes(text.data, width).rstrip()

    elif hint is Warn:
        return colorize(
            b'[!] ', 'yellow'
        ) + as_term_bytes(text.data, width).rstrip()

    elif hint is Success:
        return colorize(
            b'[+] ', 'green'
        ) + as_term_bytes(text.data, width).rstrip()

    elif hint is Info:
        return colorize(
            b'[%] ', 'grey'
        ) + as_term_bytes(text.data, width).rstrip()

    elif hint is ServiceInfo:
        return b''.join([
            colorize(b'[*] ', 'blue'),
            as_term_bytes(text.data, width).rstrip()
        ])

    elif hint is Section:
        return b'\n'.join((
            b''.join((
                colorize(b'#>#> ', 'green'),
                as_term_bytes(text.header, width),
                colorize(b'  <#<#', 'green')
            )),
            as_term_bytes(text.data, width)
        ))

    elif hint is Line:
        return as_term_bytes(
            text.dm, width
        ).join(
            as_term_bytes(v, width) for v in text.data
        )

    elif hint is List:
        return (
            as_term_bytes(
                text.caption, width
            ) + b'\n' if text.caption else b''
        ) + (
            b'\n'.join([
                (
                    b''.join((
                        (b' '*text.indent),
                        (
                            as_term_bytes(text.bullet, width) + b' '
                        ) if text.bullet else b'',
                        as_term_bytes(x, width)
                    ))
                ) for x in text.data
            ])
        )

    elif hint is Table:
        table_data = [
            {
                k: as_term_bytes(v, width) for k, v in record.items()
            } for record in text.data
        ]

        columns = set()
        for record in table_data:
            for column, value in record.items():
                if value and (not text.headers or column in text.headers):
                    columns.add(column)
                    if hasattr(value, '__iter__') and not isinstance(
                            value, bytes):
                        record[column] = b';'.join(
                            deep_as_bytes(x) for x in value
                        )

        headers = None
        if text.headers:
            headers = [
                column for column in text.headers if column in columns
            ]

        else:
            headers = list(columns)

        return b''.join((
            b'\n'*text.vspace + b'{ ' + as_term_bytes(
                text.caption, width
            ) + b' }\n' if text.caption else b'',
            table_as_bytes(table_data, wl=headers, legend=text.legend),
            b'\n'*text.vspace
        ))

    elif hint is Pygment:
        lexer = text.lexer
        text = as_term_bytes(text.data, width)
        return highlight(text, lexer, TerminalFormatter(style=PYGMENTS_STYLE))

    else:
        raise NotImplementedError(
            'as_term_bytes not implemented for {}'.format(
                hint.__class__.__name__)
        )
