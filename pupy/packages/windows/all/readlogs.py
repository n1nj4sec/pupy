# -*- encoding: utf-8 -*-

__all__ = [
    'EventLog', 'get_last_events'
]

import re

from winerror import HRESULT_CODE

from time import time

from pupwinutils.security import LookupAccountSidW as LookupAccountSid
try:
    from pupwinutils.security import StationNameByPid
except ImportError:
    StationNameByPid = None

from pywintypes import error

from win32api import MAKELANGID, LoadLibraryEx, FreeLibrary, FormatMessageW
from win32con import (
    LANG_NEUTRAL, SUBLANG_NEUTRAL,
    FORMAT_MESSAGE_FROM_HMODULE, LOAD_LIBRARY_AS_DATAFILE
)

from sys import getdefaultencoding
from os.path import expandvars, isfile
from socket import gethostbyaddr
from socket import error as socket_error

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

LANGID = MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL)
BLACKLIST = (
    'Application Error'
)

LOGON_TYPES = {
    2: 'Con',
    3: 'Net',
    4: 'Batch',
    5: 'Service',
    7: 'Unlock',
    8: 'Net(CT)',
    9: 'NewCreds',
    10: 'RDP',
    11: 'RDP(C)',
}


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

    def get_events(self, logtype, server='', filter_event_id=None, fmt=True):
        if filter_event_id is not None:
            if type(filter_event_id) in (int, long):
                filter_event_id = {filter_event_id}
            elif type(filter_event_id) in (str, unicode):
                if ',' in filter_event_id:
                    filter_event_id = set(int(x.strip()) for x in filter_event_id.split(','))
                else:
                    filter_event_id = {int(filter_event_id)}

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
                    event_id = int(HRESULT_CODE(ev_obj.EventID))

                    if filter_event_id is not None and event_id not in filter_event_id:
                        continue

                    if not ev_obj.StringInserts:
                        continue

                    message = None

                    if fmt and ev_obj.SourceName not in self._formatters_cache \
                          and ev_obj.SourceName not in BLACKLIST:
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
                    elif not fmt:
                        message = [
                            unicode(x) for x in ev_obj.StringInserts
                        ]

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
                        'EventID': event_id,
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

    def get_last_events(self, count=10, includes=[], excludes=[], eventid=None):
        events = {}

        includes = [
            re.compile(x, re.IGNORECASE | re.MULTILINE) for x in includes
        ]

        excludes = [
            re.compile(x, re.IGNORECASE | re.MULTILINE) for x in excludes
        ]

        for log in self.sources:
            amount = 0

            for event in self.get_events(log, filter_event_id=eventid):
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

def get_last_events(count=10, includes=[], excludes=[], eventid=None):
    return EventLog().get_last_events(count, includes, excludes, eventid)

def lastlog():
    events = []
    now = int(time())
    hostmap = {}

    sessions = {}

    for event in EventLog().get_events('Security', filter_event_id=(4624,4634), fmt=False):
        session_id = None

        if event['EventID'] == 4624:
            _, _, _, _, _, user, domain, session_id, logon_type, _, \
              _, _, _, _, _, _, pid, comm, ip, _ = event['msg']

            session_id = int(session_id, 16)
            logon_type = int(logon_type)
            pid = int(pid, 16)

            if logon_type in (0, 4, 5) or (pid == 0 and logon_type == 3):
                # Filter out system crap
                continue

            if comm.endswith('winlogon.exe'):
                # This is by default, who cares
                comm = None

            if logon_type == 2 or '-' in ip:
                ip = None

            if session_id not in sessions:
                sessions[session_id] = {
                    'end': None
                }

            logon_type = LOGON_TYPES.get(logon_type, logon_type)

            if ip and ip not in hostmap:
                hostname = None
                try:
                    hostname = gethostbyaddr(ip)[0]
                except socket_error:
                    pass

                hostmap[ip] = hostname

            line = logon_type
            if StationNameByPid:
                station = StationNameByPid(pid)
                if station:
                    line = '{}: {} ({})'.format(line, station, pid)

            sessions[session_id].update({
                'start': event['date'],
                'type': None,
                'host': hostmap[ip] if ip else None,
                'user': domain + '\\' + user,
                'ip': ip,
                'line': line,
                'pid': comm,
            })

        elif event['EventID'] == 4634:
            _, _, _, session_id, _ = event['msg']
            session_id = int(session_id, 16)

            if session_id not in sessions:
                sessions[session_id] = {
                    'start': None
                }

            sessions[session_id]['end'] = event['date']

        if not session_id:
            continue

        if sessions[session_id]['start'] and sessions[session_id]['end']:
            sessions[session_id]['duration'] = \
              sessions[session_id]['end'] - sessions[session_id]['start']
            events.append(sessions[session_id])
            del sessions[session_id]

    if sessions:
        orphan = [
            session for session in sessions.values() \
                  if 'start' in session and session['start']
        ]

        for session in orphan:
            session['end'] = -1
            session['duration'] = now - session['start']

        events.extend(
            sorted(orphan, key=lambda x: x['start'])
        )

    events = sorted(events, key=lambda x: x['start'], reverse=True)

    return {
        'now': now,
        'records': events
    }
