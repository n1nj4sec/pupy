# -*- encoding: utf-8 -*-

__all__ = [
    'SDJournalIterator', 'SDJournalReader', 'SDJournalException',
    'get_last_events', 'get_last_events_journald'
]

import ctypes
import time
import datetime
import re
import pwd
import os

from readlogs_generic import GenericLogReader

LIBJOURNAL = None

for lib in ['libsystemd-journal.so', 'libsystemd.so']:
    try:
        LIBJOURNAL = ctypes.CDLL(lib)
    except OSError:
        pass

if LIBJOURNAL:
    _sd_journal_open = LIBJOURNAL.sd_journal_open
    _sd_journal_open.restype = ctypes.c_int
    _sd_journal_open.argtypes = [
        ctypes.POINTER(ctypes.c_void_p), ctypes.c_int
    ]

    _sd_journal_close = LIBJOURNAL.sd_journal_close
    _sd_journal_close.restype = ctypes.c_int
    _sd_journal_close.argtypes = [
        ctypes.c_void_p
    ]

    _sd_journal_next = LIBJOURNAL.sd_journal_next
    _sd_journal_next.restype = ctypes.c_int
    _sd_journal_next.argtypes = [
        ctypes.c_void_p
    ]

    _sd_journal_previous = LIBJOURNAL.sd_journal_previous
    _sd_journal_previous.restype = ctypes.c_int
    _sd_journal_previous.argtypes = [
        ctypes.c_void_p
    ]

    _sd_journal_next_skip = LIBJOURNAL.sd_journal_next_skip
    _sd_journal_next_skip.restype = ctypes.c_int
    _sd_journal_next_skip.argtypes = [
        ctypes.c_void_p, ctypes.c_int
    ]

    _sd_journal_previous_skip = LIBJOURNAL.sd_journal_previous_skip
    _sd_journal_previous_skip.restype = ctypes.c_int
    _sd_journal_previous_skip.argtypes = [
        ctypes.c_void_p, ctypes.c_int
    ]

    _sd_journal_enumerate_fields = LIBJOURNAL.sd_journal_enumerate_fields
    _sd_journal_enumerate_fields.restype = ctypes.c_int
    _sd_journal_enumerate_fields.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_char_p)
    ]

    _sd_journal_restart_fields = LIBJOURNAL.sd_journal_restart_fields
    _sd_journal_restart_fields.restype = None
    _sd_journal_restart_fields.argtypes = [
        ctypes.c_void_p
    ]

    _sd_journal_get_data = LIBJOURNAL.sd_journal_get_data
    _sd_journal_get_data.restype = ctypes.c_int
    _sd_journal_get_data.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.POINTER(ctypes.c_char)),
        ctypes.POINTER(ctypes.c_size_t)
    ]

    _sd_journal_enumerate_data = LIBJOURNAL.sd_journal_enumerate_data
    _sd_journal_enumerate_data.restype = ctypes.c_int
    _sd_journal_enumerate_data.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.POINTER(ctypes.c_char)),
        ctypes.POINTER(ctypes.c_size_t)
    ]

    _sd_journal_seek_head = LIBJOURNAL.sd_journal_seek_head
    _sd_journal_seek_head.restype = ctypes.c_int
    _sd_journal_seek_head.argtypes = [
        ctypes.c_void_p
    ]

    _sd_journal_seek_tail = LIBJOURNAL.sd_journal_seek_tail
    _sd_journal_seek_tail.restype = ctypes.c_int
    _sd_journal_seek_tail.argtypes = [
        ctypes.c_void_p
    ]

    _sd_journal_seek_realtime_usec = LIBJOURNAL.sd_journal_seek_realtime_usec
    _sd_journal_seek_realtime_usec.restype = ctypes.c_int
    _sd_journal_seek_realtime_usec.argtypes = [
        ctypes.c_void_p,
        ctypes.c_ulonglong
    ]

    _sd_journal_get_realtime_usec = LIBJOURNAL.sd_journal_get_realtime_usec
    _sd_journal_get_realtime_usec.restype = ctypes.c_int
    _sd_journal_get_realtime_usec.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulonglong)
    ]

def _payload_to_key_value(payload):
    try:
        eq = payload.index('=')
    except ValueError:
        raise ValueError('Invalid payload')

    zb = '\x00' in payload
    fieldname = payload[:eq]

    if zb:
        try:
            payload = payload.decode('utf-8')
        except UnicodeDecodeError:
            payload = payload.decode('latin-1')

    else:
        payload = payload[eq+1:]

    return fieldname, payload

def _value_to_timestamp(value):
    stype = type(value)

    ts = 0

    if stype in (int, long):
        if value < 0:
            ts = int((time.time() - value) * 1000000)
            ts = ctypes.c_ulonglong(ts)
        else:
            ts = ctypes.c_ulonglong(int(value) * 1000000)
    else:
        if stype in (str, unicode):
            dt = None
            for formats in ('%d/%m/%Y', '%d/%m/%y %H:%M', '%d/%m/%y %H:%M:%S', '%H:%M', '%H:%M:%S'):
                try:
                    dt = datetime.datetime.strptime(value, formats)
                    if dt.year == 1900:
                        now = datetime.datetime.now()
                        dt = datetime.datetime(
                            now.year, now.month, now.day,
                            dt.hour, dt.minute, dt.second
                        )

                except ValueError:
                    pass

            if not dt:
                raise ValueError('Unknown date format')

        elif stype == datetime.timedelta:
            dt = datetime.datetime.now() + value
        elif stype != datetime.datetime:
            raise ValueError('Invalid type for since: {}'.format(stype))

        ts = int(time.mktime(dt.timetuple())*1000000)

    return ts

class SDJournalIterator(object):
    __slots__ = (
        '_journal', '_fields', '_until', '_count', '_reverse'
    )

    def __init__(self, journal, until=None, until_is_ts=False, fields=[], reverse=False):
        self._journal = journal
        self._fields = fields
        self._until = None
        self._count = None
        self._reverse = reverse
        if until:
            if until_is_ts:
                self._until = until
            else:
                self._count = until

    def next(self):
        if self._count is not None and self._count == 0:
            raise StopIteration()
        else:
            iterate = None

            if self._reverse:
                iterate = _sd_journal_previous(self._journal)
            else:
                iterate = _sd_journal_next(self._journal)

            if iterate == 0:
                raise StopIteration()

        records = {}

        data = ctypes.POINTER(ctypes.c_char)()
        data_size = ctypes.c_size_t()

        if self._fields:
            for field in self._fields:
                if _sd_journal_get_data(self._journal, field, data, data_size) != 0:
                    continue

                field, payload = _payload_to_key_value(data[:data_size.value])
                records[field] = payload
        else:
            while True:
                r = _sd_journal_enumerate_data(self._journal, data, data_size)
                if r < 0:
                    raise OSError(r)
                elif r == 0:
                    break

                field, payload = _payload_to_key_value(data[:data_size.value])
                records[field] = payload

        usecs = ctypes.c_ulonglong()
        _sd_journal_get_realtime_usec(self._journal, usecs)

        records['TIME'] = int(usecs.value / 1000000.0)

        if self._until and usecs.value > self._until:
            self._count = 0
        elif self._count is not None:
            self._count -= 1

        return records

class SDJournalException(Exception):
    pass

class SDJournalReader(object):
    __slots__ = (
        '_amount', '_last', '_fields', '_journal',
        '_since', '_until'
    )

    def __init__(self, amount=None, last=None, fields=[], since=None, until=None):
        if not LIBJOURNAL:
            raise SDJournalException('Systemd-journald library not found')

        self._last = last
        self._fields = fields
        self._since = since
        self._until = until

        self._journal = None

    def __enter__(self):
        journal = ctypes.c_void_p()
        res = _sd_journal_open(journal, 0)
        if res != 0:
            raise OSError(res)

        self._journal = journal
        return self

    def get_fields(self):
        if not self._journal:
            raise ValueError('SDJournalReader should be used in "with" statement')

        field = ctypes.c_char_p()
        fields = []
        while _sd_journal_enumerate_fields(self._journal, field) > 0:
            fields.append(field.value)

        return fields

    def __iter__(self):
        if not self._journal:
            raise ValueError('SDJournalReader should be used in "with" statement')

        until = None
        timestamp = False
        reverse = False

        if self._since:
            ts = ctypes.c_ulonglong(_value_to_timestamp(self._since))
            if _sd_journal_seek_realtime_usec(self._journal, ts) != 0:
                raise ValueError('Invalid time offset')

            if self._until:
                until = _value_to_timestamp(self._until)
                timestamp = True

        elif self._last:
            _sd_journal_seek_tail(self._journal)
            _sd_journal_previous_skip(self._journal, self._last + 1)
            until = self._last
            reverse = True

        else:
            _sd_journal_seek_tail(self._journal)
            reverse = True

        return SDJournalIterator(self._journal, until, timestamp, self._fields, reverse)

    def __exit__(self, *args):
        if self._journal:
            _sd_journal_close(self._journal)
            self._journal = None

def get_last_events_journald(count=10, includes=[], excludes=[]):
    field_mappings = {
        'MESSAGE': 'msg',
        '_HOSTNAME': 'computer',
        '_UID': 'user',
        'SYSLOG_IDENTIFIER': 'category',
        '_TRANSPORT': 'source',
        'PRIORITY': 'type',
        'TIME': 'date',
        '_EXE': 'exe',
        '_CMDLINE': 'cmd',
        '_SYSTEMD_UNIT': 'unit',
        '_SYSTEMD_USER_UNIT': 'user-unit',
    }

    priorities = (
        'EMERGENCY', 'CRITICAL', 'ALERT', 'ERROR',
        'WARNING', 'NOTICE', 'INFO', 'DEBUG'
    )

    includes = [
        re.compile(x, re.IGNORECASE | re.MULTILINE) for x in includes
    ]

    excludes = [
        re.compile(x, re.IGNORECASE | re.MULTILINE) for x in excludes
    ]

    events = SDJournalReader(fields=field_mappings.keys())
    source_events = {}

    amount = 0

    with events:
        for event in events:
            event = {
                v:event.get(k, '') for k,v in field_mappings.iteritems()
            }

            if event.get('user') != '':
                try:
                    event['user'] = pwd.getpwuid(int(event['user'])).pw_name
                except KeyError:
                    pass

            event['type'] = priorities[int(event['type'])]

            append = not includes and not excludes
            excluded = False

            for value in event.values():
                if append:
                    break

                if type(value) not in (str, unicode):
                    try:
                        value = str(value)
                    except TypeError:
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

            if not append:
                continue

            source = event.pop('source')

            if source not in source_events:
                source_events[source] = []

            source_events[source].append(event)

            amount += 1

            if amount == count:
                break

    return source_events

def get_last_events(count=10, includes=[], excludes=[]):
    try:
        source_events = get_last_events_journald(count, includes, excludes)
    except SDJournalException:
        source_events = {}

    for d in ['/var/log']:
        if os.path.isdir(d):
            events = GenericLogReader(d).get_last_events(count, includes, excludes)
            source_events.update(events)

    return source_events
