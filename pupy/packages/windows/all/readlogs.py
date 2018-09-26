# -*- encoding: utf-8 -*-

import winerror
import re
import datetime

from win32evtlogutil import SafeFormatMessage
from win32security import LookupAccountSid
from pywintypes import error

from win32con import (
    EVENTLOG_AUDIT_FAILURE,
    EVENTLOG_AUDIT_SUCCESS,
    EVENTLOG_INFORMATION_TYPE,
    EVENTLOG_WARNING_TYPE,
    EVENTLOG_ERROR_TYPE
)

from _winreg import (
    OpenKeyEx, EnumKey, CloseKey,
    HKEY_LOCAL_MACHINE, KEY_READ
)

from win32evtlog import (
    OpenEventLog, ReadEventLog, CloseEventLog,
    GetNumberOfEventLogRecords,
    EVENTLOG_BACKWARDS_READ, EVENTLOG_SEQUENTIAL_READ
)

def to_utc_timestamp(d):
    return (d - datetime.datetime.utcfromtimestamp(0)).total_seconds()

class EventLog(object):
    event_types = {
        EVENTLOG_AUDIT_FAILURE: 'FAILURE',
        EVENTLOG_AUDIT_SUCCESS: 'SUCCESS',
        EVENTLOG_INFORMATION_TYPE: 'INFO',
        EVENTLOG_WARNING_TYPE: 'WARNING',
        EVENTLOG_ERROR_TYPE: 'ERROR'
    }

    def __init__(self):
        self.sources = self.get_types()

    def get_types(self):
        sources = []

        key = OpenKeyEx(
            HKEY_LOCAL_MACHINE,
            r'SYSTEM\CurrentControlSet\Services\EventLog',
            0, KEY_READ
        )

        try:
            idx = 0
            while True:
                try:
                    source = EnumKey(key, idx)
                    log = OpenEventLog('', source)
                    # If failed, then provider is invalid or inaccessible
                    GetNumberOfEventLogRecords(log)
                    CloseEventLog(log)

                    sources.append(source)

                except error, e:
                    if e.winerror != 6:
                        raise

                except WindowsError:
                    break

                idx += 1

        finally:
            CloseKey(key)

        return sources

    def get_events_count(self):
        events_count = {}

        for logtype in self.sources:
            log = OpenEventLog('', logtype)
            if not log:
                continue

            try:
                events_count[logtype] = GetNumberOfEventLogRecords(log)
                CloseEventLog(log)

            except error, e:
                if e.winerror != 6:
                    raise

        return events_count

    def get_events(self, logtype, server=''):
        log = OpenEventLog(server, logtype)
        if not log:
            return

        flags = EVENTLOG_BACKWARDS_READ|EVENTLOG_SEQUENTIAL_READ
        events = ReadEventLog(log, flags, 0)

        try:
            events = True
            while events:
                events = ReadEventLog(log, flags, 0)
                for ev_obj in events:
                    user = ''

                    if ev_obj.Sid is not None:
                        try:
                            domain, domain_user, _ = LookupAccountSid(server, ev_obj.Sid)
                            user = u'{}\\{}'.format(domain, domain_user)
                        except error:
                            user = str(ev_obj.Sid)

                    yield {
                        'id': int(winerror.HRESULT_CODE(ev_obj.EventID)),
                        'record': ev_obj.RecordNumber,
                        'date': to_utc_timestamp(
                            datetime.datetime.strptime(
                                ev_obj.TimeGenerated.Format(), '%m/%d/%y %H:%M:%S')),
                        'computer': ev_obj.ComputerName,
                        'category': ev_obj.EventCategory,
                        'msg': SafeFormatMessage(ev_obj, logtype),
                        'source': ev_obj.SourceName,
                        'type': EventLog.event_types.get(ev_obj.EventType, 'UNKNOWN'),
                        'user': user
                    }
        except GeneratorExit:
            pass

        finally:
            CloseEventLog(log)

    def get_last_events(self, count=10, includes=[], excludes=[]):
        events = {}

        includes = [
            re.compile(x) for x in includes
        ]

        excludes = [
            re.compile(x) for x in excludes
        ]

        for source in self.sources:
            source_events = []
            amount = 0

            for event in self.get_events(source):
                append = not includes and not excludes

                for value in event.values():
                    if append:
                        break

                    if type(value) not in (str, unicode):
                        value = str(value)

                    for exclude in excludes:
                        if exclude.search(value):
                            append = False
                            break

                    for include in includes:
                        if include.search(value):
                            append = True
                            break

                if not append:
                    continue

                source_events.append(event)

                amount += 1
                if amount == count:
                    break

            events[source] = source_events

        return events

def get_last_events(count=10, includes=[], excludes=[]):
    return EventLog().get_last_events(count, includes, excludes)
