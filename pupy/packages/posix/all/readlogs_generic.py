# -*- encoding: utf-8 -*-

__all__ = [
  'GenericLogReader'
]

import datetime
import re
import os

def to_timestamp(d):
    return (d - datetime.datetime.fromtimestamp(0)).total_seconds()

def ytail(f):
    BUFSIZ = 5
    CR = '\n'
    data = ''

    f.seek(0, os.SEEK_END)

    fsize = f.tell()
    block = 0
    exit = False

    while not exit:
        step = (block * BUFSIZ)

        if step >= fsize:
            f.seek(0)
            newdata = f.read(BUFSIZ - (abs(step) - fsize))
            exit = True
        else:
            f.seek(fsize - step)
            newdata = f.read(BUFSIZ)

        block += 1
        data = newdata + data

        if CR in data:
            lines = data.split(CR)
            data, lines = lines[0], lines[1:]
            for line in reversed(lines):
                yield line

    if data:
        yield data

def try_get_mtime(x):
    try:
        return os.stat(x).st_mtime
    except OSError:
        return 0

class GenericLogReader(object):
    parsers = [
        '_debian_log_parser'
    ]

    _debian_generic_parser = re.compile(
        r'^([A-Z][a-z]{2}\s+\d+\s\d\d:\d\d:\d\d)\s(\S+)\s([^:]+):\s+(.*)')

    def __init__(self, logs=u'/var/log'):
        self.files = {}

        for root, _, files in os.walk(logs):
            for logfile in files:
                logfile = os.path.join(root, logfile)
                if not os.path.isfile(logfile):
                    continue

                try:
                    parser = self._get_parser(logfile)
                except IOError:
                    continue

                if parser:
                    self.files[logfile] = parser

    def get_last_events(self, count=10, includes=[], excludes=[]):
        includes = [
            re.compile(x, re.IGNORECASE | re.MULTILINE) for x in includes
        ]

        excludes = [
            re.compile(x, re.IGNORECASE | re.MULTILINE) for x in excludes
        ]

        events = {}

        for source in sorted(self.files.keys(), key=try_get_mtime, reverse=True):
            parser = self.files[source]

            for item in parser(source):
                category = item.pop('category')
                append = not includes and not excludes
                excluded = False

                if category not in events:
                    events[category] = []

                if len(events[category]) >= count:
                    break

                for value in item.values():
                    if type(value) not in (str, unicode):
                        continue

                    for exclude in excludes:
                        if exclude.search(value):
                            append = False
                            excluded = True
                            break

                    if excluded:
                        break

                    for include in includes:
                        if include.search(value):
                            append = True
                            break

                if not includes and not excluded:
                    append = True

                if append:
                    events[category].append(item)

        return events

    def _debian_log_parser(self, logfile, probe=False):

        category = os.path.basename(logfile)

        if '-' in category:
            category = category.split('-')[0]
        elif '.' in category:
            category = category.split('.')[0]

        with open(logfile) as log:
            if probe:
                line = log.readline().strip()
                yield bool(GenericLogReader._debian_generic_parser.match(line))
                return

            mtime = datetime.datetime.fromtimestamp(os.fstat(log.fileno()).st_mtime)
            year = str(mtime.year)

            for line in ytail(log):
                line = line.strip()
                if '\n' in line:
                    # Something went wrong
                    return

                match = GenericLogReader._debian_generic_parser.match(line)
                if not match:
                    continue

                date, hostname, sender, message = match.groups()
                pid = ''
                etype = ''

                date = datetime.datetime.strptime(date+' '+year, '%b %d %H:%M:%S %Y')

                if '[' in sender:
                    pid_start = sender.index('[')
                    pid_data = sender[pid_start+1:-1]
                    sender = sender[:pid_start]
                    try:
                        pid = int(pid_data)
                    except ValueError:
                        etype = pid

                yield {
                    'date': to_timestamp(date),
                    'computer': hostname,
                    'category': category,
                    'msg': message,
                    'user': '',
                    'type': etype,
                    'pid': pid
                }

    def _get_parser(self, logfile):
        for parser in GenericLogReader.parsers:
            parser = getattr(self, parser)
            if next(parser(logfile, probe=True)):
                return parser
