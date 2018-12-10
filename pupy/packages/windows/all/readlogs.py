# -*- encoding: utf-8 -*-

__all__ = [
    'EventLog', 'get_last_events'
]

import winerror
import re

from win32security import LookupAccountSid
from pywintypes import error
from win32api import MAKELANGID, LoadLibraryEx, FreeLibrary, FormatMessageW
from win32con import (
    LANG_NEUTRAL, SUBLANG_NEUTRAL,
    FORMAT_MESSAGE_FROM_HMODULE, LOAD_LIBRARY_AS_DATAFILE
)

from sys import getdefaultencoding
from os.path import expandvars, isfile

from win32con import (
    EVENTLOG_AUDIT_FAILURE,
    EVENTLOG_AUDIT_SUCCESS,
    EVENTLOG_INFORMATION_TYPE,
    EVENTLOG_WARNING_TYPE,
    EVENTLOG_ERROR_TYPE
)

from _winreg import (
    OpenKeyEx, EnumKey, CloseKey, QueryValueEx,
    HKEY_LOCAL_MACHINE, KEY_READ
)

from win32evtlog import (
    OpenEventLog, ReadEventLog, CloseEventLog,
    GetNumberOfEventLogRecords,
    EVENTLOG_BACKWARDS_READ, EVENTLOG_SEQUENTIAL_READ
)

from datetime import datetime

LANGID = MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL)
BLACKLIST = (
    'Application Error'
)

class EventLog(object):
    event_types = {
        EVENTLOG_AUDIT_FAILURE: 'FAILURE',
        EVENTLOG_AUDIT_SUCCESS: 'SUCCESS',
        EVENTLOG_INFORMATION_TYPE: 'INFO',
        EVENTLOG_WARNING_TYPE: 'WARNING',
        EVENTLOG_ERROR_TYPE: 'ERROR'
    }

    def __init__(self):
        self._exceptions = {}
        self._formatters_cache = {}

        self.sources = self.get_types()

    def _iter_log_names(self):
        dups = set()

        for well_known in ('Application', 'Security', 'System'):
            dups.add(well_known)
            yield well_known

        key = OpenKeyEx(
            HKEY_LOCAL_MACHINE,
            ur'SYSTEM\CurrentControlSet\Services\EventLog',
            0, KEY_READ
        )

        try:
            idx = 0
            while True:
                try:
                    source = EnumKey(key, idx)
                    if source in dups:
                        continue

                    dups.add(source)

                    if type(source) == str:
                        source = source.decode(getdefaultencoding())

                    yield source

                except WindowsError:
                    break

                finally:
                    idx += 1

        finally:
            CloseKey(key)

    def get_types(self):
        sources = []

        for logname in self._iter_log_names():
            handle = None

            try:
                handle = OpenEventLog('', logname)
                if not handle:
                    continue

                # If failed, then provider is invalid or inaccessible
                GetNumberOfEventLogRecords(handle)
                CloseEventLog(handle)

                sources.append(logname)

            except error, e:
                if e.winerror not in (6, 87, 1314):
                    raise

                self._exceptions[logname] = (e, handle)

            except WindowsError, e:
                self._exceptions[logname] = (e, handle)

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

        UTC_OFFSET_TIMEDELTA = (
            datetime.now() - datetime.utcnow()
        ).total_seconds()

        log = OpenEventLog(server, logtype)
        if not log:
            return

        flags = EVENTLOG_BACKWARDS_READ|EVENTLOG_SEQUENTIAL_READ

        try:
            events = ReadEventLog(log, flags, 0)
        except error, e:
            if e.winerror not in {23}:
                raise

            return

        try:
            events = True
            while events:
                try:
                    events = ReadEventLog(log, flags, 0)
                except error, e:
                    if e.winerror not in {23}:
                        raise ValueError

                    return

                if not events:
                    break

                for ev_obj in events:
                    if not ev_obj.StringInserts:
                        continue

                    message = None

                    if ev_obj.SourceName not in self._formatters_cache and ev_obj.SourceName not in BLACKLIST:
                        source_name = ev_obj.SourceName
                        if type(source_name) == str:
                            source_name = source_name.decode(getdefaultencoding())

                        subkey = ur'SYSTEM\CurrentControlSet\Services\EventLog\{}\{}'.format(
                            logtype, source_name
                        )

                        try:
                            subkey = subkey.encode(getdefaultencoding())
                        except UnicodeEncodeError:
                            subkey = subkey.encode('utf-8')

                        try:
                            key = OpenKeyEx(HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ)
                        except WindowsError:
                            continue

                        try:
                            dllNames, _ = QueryValueEx(key, 'EventMessageFile')

                            for dllName in dllNames.split(';'):
                                dllName = expandvars(dllName.strip())
                                if not isfile(dllName):
                                    continue

                                dllHandle = LoadLibraryEx(
                                    dllName, 0, LOAD_LIBRARY_AS_DATAFILE)

                                if not dllHandle:
                                    continue

                                try:
                                    message = FormatMessageW(FORMAT_MESSAGE_FROM_HMODULE,
                                        dllHandle, ev_obj.EventID, LANGID, ev_obj.StringInserts)

                                except error:
                                    FreeLibrary(dllHandle)
                                    continue

                                if message:
                                    self._formatters_cache[ev_obj.SourceName] = dllHandle
                                    break

                            if not message:
                                self._formatters_cache[ev_obj.SourceName] = None
                                message = '\n'.join(ev_obj.StringInserts)

                        except WindowsError:
                            self._formatters_cache[ev_obj.SourceName] = None

                    elif ev_obj.SourceName in BLACKLIST or not self._formatters_cache[ev_obj.SourceName]:
                        message = '\n'.join(ev_obj.StringInserts)
                    else:
                        try:
                            message = FormatMessageW(
                                FORMAT_MESSAGE_FROM_HMODULE,
                                self._formatters_cache[ev_obj.SourceName],
                                ev_obj.EventID, LANGID, ev_obj.StringInserts)

                        except error:
                            message = '\n'.join(ev_obj.StringInserts)

                    user = ''

                    if ev_obj.Sid is not None:
                        try:
                            domain, domain_user, _ = LookupAccountSid(server, ev_obj.Sid)
                            user = u'{}\\{}'.format(domain, domain_user)
                        except error:
                            user = str(ev_obj.Sid)

                    if not message:
                        continue

                    yield {
                        'id': int(winerror.HRESULT_CODE(ev_obj.EventID)) + UTC_OFFSET_TIMEDELTA,
                        'EventID': int(winerror.HRESULT_CODE(ev_obj.EventID)),
                        'record': ev_obj.RecordNumber,
                        'date': int(ev_obj.TimeGenerated),
                        'computer': ev_obj.ComputerName,
                        'category': ev_obj.EventCategory,
                        'msg': message,
                        'source': logtype + ': ' + ev_obj.SourceName,
                        'type': EventLog.event_types.get(ev_obj.EventType, 'UNKNOWN'),
                        'user': user
                    }
        except GeneratorExit:
            pass

        finally:
            for source in self._formatters_cache.keys():
                if self._formatters_cache[source]:
                    FreeLibrary(self._formatters_cache[source])
                del self._formatters_cache[source]

            CloseEventLog(log)

    def get_last_events(self, count=10, includes=[], excludes=[]):
        events = {}

        includes = [
            re.compile(x, re.IGNORECASE | re.MULTILINE) for x in includes
        ]

        excludes = [
            re.compile(x, re.IGNORECASE | re.MULTILINE) for x in excludes
        ]

        for log in self.sources:
            amount = 0

            for event in self.get_events(log):
                source = event.pop('source')

                if source not in events:
                    events[source] = []

                append = not includes and not excludes
                excluded = False

                for key, value in event.iteritems():
                    if append:
                        break

                    if type(value) not in (str, unicode):
                        value = str(value)

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

                events[source].append(event)

                amount += 1
                if amount == count:
                    break

        return events

def get_last_events(count=10, includes=[], excludes=[]):
    return EventLog().get_last_events(count, includes, excludes)
