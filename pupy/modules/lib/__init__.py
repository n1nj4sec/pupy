# -*- coding: utf-8 -*-

from datetime import datetime

def size_human_readable(num, suffix=''):
    try:
        num = int(num)
        for unit in [suffix or 'B','K','M','G','T','P','E','Z']:
            if abs(num) < 1024.0:
                return "%3.1f%s%s" % (num, unit, suffix)
            num /= 1024.0
        return "%.1f%s%s" % (num, 'Yi', suffix)
    except:
        return '0.0B'

def file_timestamp(timestamp, time=False):
    try:
        d = datetime.fromtimestamp(timestamp)
        if time:
            return str(d.strftime('%d/%m/%y %H:%M:%S'))
        else:
            return str(d.strftime('%d/%m/%y'))
    except:
        return '00/00/00'

def to_utf8(value):
    if type(value) == unicode:
        return value
    elif type(value) == str:
        try:
            return value.decode('utf-8')
        except:
            return value.decode('latin1', errors='ignore')
    else:
        return value
