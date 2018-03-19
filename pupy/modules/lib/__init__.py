# -*- coding: utf-8 -*-

def size_human_readable(num, suffix='B'):
    try:
        num = int(num)
        for unit in ['','Ki','Mi','Gi','Ti','Pi','Ei','Zi']:
            if abs(num) < 1024.0:
                return "%3.1f %s%s" % (num, unit, suffix)
            num /= 1024.0
        return "%.1f %s%s" % (num, 'Yi', suffix)
    except:
        return '0.00 B'

def file_timestamp(timestamp):
    try:
        d = datetime.fromtimestamp(timestamp)
        return str(d.strftime("%d/%m/%y"))
    except:
        return '00/00/00'

def to_utf8(value):
    if type(value) == unicode:
        return value
    try:
        return value.decode('utf-8')
    except:
        return value.decode('latin1', errors='ignore')
