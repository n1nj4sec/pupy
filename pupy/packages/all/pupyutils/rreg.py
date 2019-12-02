# -*- coding: utf-8 -*-

__all__ = [
  'Key', 'search', 'enum',
  'set', 'get', 'rm'
]

import re
import sys
import struct
import threading
import traceback
import rpyc

from pupyutils.psexec import ConnectionInfo

from impacket.dcerpc.v5.dcom.wmi import ENCODED_STRING
from impacket.structure import Structure


ERROR_SUCCESS = 0
ERROR_MORE_DATA = 234

REG_NONE = 0
REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD = 4
REG_DWORD_BIG_ENDIAN = 5
REG_DWORD_LITTLE_ENDIAN = 4
REG_QWORD = 11
REG_LINK = 6
REG_MULTI_SZ = 7
REG_RESOURCE_LIST = 8
REG_FULL_RESOURCE_DESCRIPTOR = 9
REG_RESOURCE_REQUIREMENTS_LIST = 10

REG_OPTION_RESERVED = 0x0000
REG_OPTION_NON_VOLATILE = 0x0000
REG_OPTION_VOLATILE = 0x0001
REG_OPTION_CREATE_LINK = 0x0002
REG_OPTION_BACKUP_RESTORE = 0x0004
REG_OPTION_OPEN_LINK = 0x0008

KEY_QUERY_VALUE = 0x0001
KEY_SET_VALUE = 0x0002
KEY_CREATE_SUB_KEY = 0x0004
KEY_ENUMERATE_SUB_KEYS = 0x0008
KEY_NOTIFY = 0x0010
KEY_CREATE_LINK = 0x0020
KEY_WOW64_32KEY = 0x0200
KEY_WOW64_64KEY = 0x0100
KEY_WOW64_RES = 0x0300
READ_CONTROL = 0x00020000
SYNCHRONIZE = 0x00100000
STANDARD_RIGHTS_READ = READ_CONTROL
STANDARD_RIGHTS_WRITE = READ_CONTROL
STANDARD_RIGHTS_ALL = 0x001F0000

KEY_READ = (
    (
        STANDARD_RIGHTS_READ | \
        KEY_QUERY_VALUE | \
        KEY_ENUMERATE_SUB_KEYS | \
        KEY_NOTIFY
    ) & (~SYNCHRONIZE)
)
KEY_WRITE = (
    (
        STANDARD_RIGHTS_WRITE | \
        KEY_SET_VALUE | \
        KEY_CREATE_SUB_KEY
    ) & (~SYNCHRONIZE)
)
KEY_ALL_ACCESS = (
    (
        STANDARD_RIGHTS_ALL | \
        KEY_QUERY_VALUE | \
        KEY_SET_VALUE | \
        KEY_CREATE_SUB_KEY | \
        KEY_ENUMERATE_SUB_KEYS | \
        KEY_NOTIFY | \
        KEY_CREATE_LINK
    ) & (~SYNCHRONIZE)
)


HKEY_CLASSES_ROOT = 0x80000000
HKEY_CURRENT_USER = 0x80000001
HKEY_LOCAL_MACHINE = 0x80000002
HKEY_USERS = 0x80000003
HKEY_PERFORMANCE_DATA = 0x80000004
HKEY_CURRENT_CONFIG = 0x80000005
HKEY_DYN_DATA = 0x80000006

WELL_KNOWN_KEYS = {
    'HKEY_LOCAL_MACHINE': HKEY_LOCAL_MACHINE,
    'HKLM': HKEY_LOCAL_MACHINE,
    'HKEY_CURRENT_USER': HKEY_CURRENT_USER,
    'HKCU': HKEY_CURRENT_USER,
    'HKEY_CURRENT_CONFIG': HKEY_CURRENT_CONFIG,
    'HKCC': HKEY_CURRENT_CONFIG,
    'HKEY_CLASSES_ROOT': HKEY_CLASSES_ROOT,
    'HKCR': HKEY_CLASSES_ROOT,
    'HKEY_USERS': HKEY_USERS,
    'HKU': HKEY_USERS,
    'HKEY_PERFORMANCE_DATA': HKEY_PERFORMANCE_DATA,
    'HKPD': HKEY_PERFORMANCE_DATA,
}

WELL_KNOWN_TYPES = {
    int: REG_DWORD,
    str: REG_SZ,
    unicode: REG_SZ,
}

WELL_KNOWN_TYPES_NAMES = {
    REG_DWORD: 'DWORD',
    REG_QWORD: 'LE64',
    REG_BINARY: 'BINARY',
    REG_DWORD_LITTLE_ENDIAN: 'LE32',
    REG_DWORD_BIG_ENDIAN: 'BE32',
    REG_EXPAND_SZ: 'EXPAND_SZ',
    REG_LINK: 'LINK',
    REG_MULTI_SZ: 'MULTI_SZ',
    REG_NONE: 'NONE',
    REG_RESOURCE_LIST: 'RESOURCE',
    REG_FULL_RESOURCE_DESCRIPTOR: 'RESOURCE_DESCRIPTOR',
    REG_RESOURCE_REQUIREMENTS_LIST: 'RESOURCE_REQUIREMENTS_LIST',
    REG_SZ: 'SZ'
}

WELL_KNOWN_TYPES_GETTERS = {
    REG_DWORD: ('GetDWORDValue', 'uValue'),
    REG_QWORD: ('GetQWORDValue', 'uValue'),
    REG_BINARY: ('GetBinaryValue', 'uValue'),
    REG_DWORD_LITTLE_ENDIAN: ('GetDWORDValue', 'uValue'),
    REG_DWORD_BIG_ENDIAN: ('GetDWORDValue', 'uValue'),
    REG_EXPAND_SZ: ('GetExpandedStringValue', 'sValue'),
    REG_MULTI_SZ: ('GetMultiStringValue', 'sValue'),
    REG_SZ: ('GetStringValue', 'sValue'),
}

WELL_KNOWN_TYPES_SETTERS = {
    REG_DWORD: 'SetDWORDValue',
    REG_QWORD: 'SetQWORDValue',
    REG_BINARY: 'SetBinaryValue',
    REG_DWORD_LITTLE_ENDIAN: 'SetDWORDValue',
    REG_DWORD_BIG_ENDIAN: 'SetDWORDValue',
    REG_EXPAND_SZ: 'SetExpandedStringValue',
    REG_MULTI_SZ: 'SetMultiStringValue',
    REG_SZ: 'SetStringValue',
}


# Workaround for impacket

def ENCODED_STRING__setitem__(self, key, value):
    if key == 'Character' and isinstance(value, unicode):
        value = value.encode('utf-16le')
        Structure.__setitem__(self, 'Encoded_String_Flag', 0x1)
        self.structure = self.tunicode
        self.isUnicode = True

    Structure.__setitem__(self, key, value)


setattr(ENCODED_STRING, '__setitem__', ENCODED_STRING__setitem__)


def value_to_bytes(value, ktype):
    if isinstance(value, str):
        return value

    if ktype in (REG_SZ, REG_EXPAND_SZ):
        if isinstance(value, unicode):
            value = value.encode('utf-16le')
        else:
            value = str(value)

    elif ktype == REG_MULTI_SZ:
        value = u'\0'.join(value) + u'\0\0'

    elif ktype == REG_DWORD:
        value = struct.pack('<i', value)

    elif ktype == REG_DWORD_LITTLE_ENDIAN:
        value = struct.pack('<i', value)

    elif ktype == REG_DWORD_BIG_ENDIAN:
        value = struct.pack('>i', value)

    elif ktype == REG_QWORD:
        value = struct.pack('<q', value)

    return value


def as_unicode(value):
    if isinstance(value, unicode):
        return value

    elif isinstance(value, str):
        try:
            value = value.decode(sys.getfilesystemencoding())
        except UnicodeError:
            try:
                value = value.decode('utf-8')
            except UnicodeError:
                value = value.decode('latin-1')

    return value


def as_str(value):
    if isinstance(value, str):
        return value
    elif isinstance(value, unicode):
        return value.encode('utf-8')

    return str(value)


def as_local(value):
    if isinstance(value, str):
        return value

    elif isinstance(value, unicode):
        return value.encode(sys.getfilesystemencoding())

    return value


class RRegError(ValueError):
    pass


def raise_on_error(result):
    if result.ReturnValue:
        raise RRegError(result.ReturnValue)


class KeyIter(object):
    __slots__ = (
        'handle', 'orig_name', 'key',
        'sub', 'idx',
        'max_value_size', 'max_data_size'
    )

    def __init__(self, orig_name, key, sub, handle):
        self.orig_name = orig_name
        self.key = key
        self.sub = sub
        self.handle = handle
        self.idx = 0
        self.max_value_size = None
        self.max_data_size = None

    def __iter__(self):
        result = self.handle.EnumKey(self.key, self.sub)
        raise_on_error(result)

        if result.sNames:
            for name in result.sNames:
                yield Key(self.handle, u'\\'.join([self.orig_name, name]))

        result = self.handle.EnumValues(self.key, self.sub)
        raise_on_error(result)

        if not result.sNames:
            return

        for name, ktype in zip(result.sNames, result.Types):
            supported_getter = WELL_KNOWN_TYPES_GETTERS.get(ktype)
            if supported_getter is None:
                # Unsupported type, omit
                continue

            getter, field = supported_getter
            method = getattr(self.handle, getter)
            wmivalue = method(self.key, self.sub, name)
            raise_on_error(wmivalue)

            value = getattr(wmivalue, field)

            yield Value(self.orig_name, name, value, ktype)



class Value(object):
    __slots__ = ('parent', 'name', 'value', 'type')

    def __init__(self, parent, name, value, ktype):
        self.parent = parent
        self.name = name
        self.value = value
        self.type = ktype

    def __repr__(self):
        return 'Value({}, {}, {}, {})'.format(
            repr(self.parent),
            repr(self.name),
            repr(self.value),
            repr(self.type)
        )


class Key(object):
    __slots__ = (
        'arg', 'key', 'sub', 'handle', '_values'
    )

    def __init__(self, handle, key):
        sub_key = None
        top_key = None

        key = as_unicode(key)
        for wkk, wrk in WELL_KNOWN_KEYS.iteritems():
            if key == wkk:
                top_key = wrk
                sub_key = ''
            elif key.startswith((wkk+'\\', wkk+'/')):
                top_key = wrk
                sub_key = key[len(wkk)+1:]
                break

        if not top_key:
            raise KeyError(key)

        sub_key = sub_key.strip('\\')

        self.key = top_key
        self.sub = sub_key
        self.arg = key
        self.handle = handle

        self._values = {}

    @property
    def name(self):
        return self.arg.split('\\')[-1]

    @property
    def parent(self):
        return u'\\'.join(self.arg.split('\\')[:-1])

    def _query_value(self, attr):
        if not self._values:
            result = self.handle.EnumValues(self.key, self.sub)
            raise_on_error(result)

            if result.sNames:
                self._values = dict(zip(result.sNames, result.Types))
            else:
                self._values = {}

        if attr not in self._values:
            raise KeyError(attr)

        ktype = self._values[attr]

        getter = WELL_KNOWN_TYPES_GETTERS.get(ktype)
        method = getattr(self.handle, getter)
        wmivalue = method(self.key, self.sub, attr)
        raise_on_error(wmivalue)

        value = getattr(wmivalue, attr)
        return Value(self.arg, attr, value, ktype)

    def __iter__(self):
        for value in KeyIter(self.arg, self.key, self.sub, self.handle):
            yield value

    def __str__(self):
        return as_str(self.arg)

    def __unicode__(self):
        return as_unicode(self.arg)

    def __repr__(self):
        return repr(self.arg)

    def __int__(self):
        return repr(self.arg)

    def __delitem__(self, attr):
        result = self.handle.DeleteValue(self.key, self.sub, attr)
        if result.ReturnValue == 2:
            result = self.handle.DeleteKey(self.key, self.sub + '\\' + attr)

        if result.ReturnValue:
            raise ValueError(result.ReturnValue)

    def __getitem__(self, attr):
        return self._query_value(attr)

    def __setitem__(self, attr, value):
        vtype = type(value)

        if vtype not in WELL_KNOWN_TYPES and vtype is not Value:
            raise TypeError('setattr only supported for str/int')

        ktype = value.type if vtype is Value else WELL_KNOWN_TYPES[vtype]
        if vtype is Value:
            value = value.value
        elif ktype == REG_SZ and '%' in value:
            ktype = REG_EXPAND_SZ

        method = WELL_KNOWN_TYPES_SETTERS.get(ktype)

        setter = getattr(self.handle, method)
        result = setter(self.key, self.sub, attr, value)

        raise_on_error(result)


def __search(
    regprov, completed, data_cb, close_cb,
    term, roots=('HKU', 'HKLM', 'HKCC'), key=True,
        name=True, value=True, regex=False,
        ignorecase=False, first=False, equals=False):

    compare = None

    def contains(u_term, b_term, i_term, value, ignorecase=False):
        if isinstance(value, unicode):
            if ignorecase:
                value = value.lower()
            return u_term in value
        elif isinstance(value, (int, long)):
            if i_term is None:
                return False
            return i_term == value
        elif isinstance(value, str):
            if ignorecase:
                value = value.lower()
            return b_term in value
        elif isinstance(value, list):
            return any(
                contains(
                    u_term, b_term, i_term, x, ignorecase
                ) for x in value
            )
        else:
            return False

    def issame(u_term, b_term, i_term, value, ignorecase=False):
        if isinstance(value, unicode):
            if ignorecase:
                value = value.lower()
            return u_term == value
        elif isinstance(value, (int, long)):
            if i_term is None:
                return False
            return i_term == value
        elif isinstance(value, str):
            if ignorecase:
                value = value.lower()
            return b_term == value
        elif isinstance(value, list):
            return any(
                issame(
                    u_term, b_term, i_term, x, ignorecase
                ) for x in value
            )
        else:
            return False

    if ignorecase:
        term = term.lower()

    u_term = as_unicode(term)
    b_term = as_str(term)

    try:
        i_term = int(term)
    except ValueError:
        i_term = None

    if regex:
        term_re = re.compile(
            u_term,
            re.UNICODE | \
                re.MULTILINE | \
                    (re.IGNORECASE if ignorecase else 0))

        if equals:
            compare = lambda x: \
                term_re.match(x) if isinstance(x, unicode) else False
        else:
            compare = lambda x: \
                term_re.search(x) if isinstance(x, unicode) else False

    else:
        if equals:
            compare = lambda x: issame(u_term, b_term, i_term, x, ignorecase)
        else:
            compare = lambda x: contains(u_term, b_term, i_term, x, ignorecase)

    if type(roots) in (str, unicode):
        roots = [roots]

    def _walk(root, data_cb):
        if completed.is_set():
            return

        for kv in root:
            if completed.is_set():
                return

            if isinstance(kv, Key):
                if key and compare(kv.name):
                    data_cb((True, kv.name))
                    if first:
                        completed.set()
                        return

                try:
                    _walk(kv, data_cb)
                except RRegError:
                    pass

            elif isinstance(kv, Value):
                if (
                    name and compare(kv.name)
                ) or (
                    value and compare(kv.value)
                ):
                    data_cb((
                        False, kv.parent, kv.name,
                        kv.value, kv.type))
                    if first:
                        completed.set()
                        return
            else:
                raise TypeError(
                    'Unknown type {} in search'.format(
                        type(kv)))

    try:
        for root in roots:
            try:
                _walk(Key(regprov, root), data_cb)
            except RRegError:
                continue

    except Exception as e:
        data_cb((None, '{}\n{}'.format(e, traceback.format_exc())))

    finally:
        if completed.is_set():
            data_cb((None, 'Interrupted'))

        completed.set()
        close_cb()


def _search(
    conninfo, completed, data_cb, close_cb,
    term, roots=('HKU', 'HKLM', 'HKCC'), key=True,
        name=True, value=True, regex=False,
        ignorecase=False, first=False, equals=False):

    with conninfo:
        iWbemServices = conninfo.create_wbem('//./root/cimv2')
        regprov, _ = iWbemServices.GetObject('StdRegprov')

        __search(
            regprov, completed, data_cb, close_cb,
            term, roots, key, name, value, regex,
            ignorecase, first, equals
        )


def search(
    host, port,
    user, domain,
    password, ntlm,
    data_cb, close_cb,
    term, roots=('HKU', 'HKLM', 'HKCC'), key=True,
        name=True, value=True, regex=False,
        ignorecase=False, first=False, equals=False, timeout=30):

    conninfo = ConnectionInfo(
        host, port, user, domain, password, ntlm, timeout=timeout
    )

    data_cb = rpyc.async(data_cb)
    close_cb = rpyc.async(close_cb)

    completed = threading.Event()
    worker = threading.Thread(
        name='Reg:Search',
        target=_search,
        args=(
            conninfo,
            completed,
            data_cb, close_cb,
            term, roots, key,
            name, value, regex,
            ignorecase, first, equals
        )
    )

    worker.start()

    def interrupt():
        completed.set()
        worker.join()

    return interrupt


def enum(
    host, port,
    user, domain,
        password, ntlm,
        path=None, timeout=30):

    conninfo = ConnectionInfo(
        host, port, user, domain, password, ntlm, timeout=timeout
    )

    if path is None:
        return [(
            True, unicode(item)
        ) for item in WELL_KNOWN_KEYS]

    try:
        tupleized = []

        with conninfo:
            iWbemServices = conninfo.create_wbem('//./root/cimv2')
            regprov, _ = iWbemServices.GetObject('StdRegprov')

            for item in Key(regprov, path):
                if type(item) == Key:
                    tupleized.append((True, unicode(item)))
                else:
                    tupleized.append((
                        False, item.parent, item.name,
                        item.value, item.type))

            return tuple(tupleized)

    except KeyError:
        return None


def set(
    host, port,
    user, domain,
    password, ntlm,
        path, name, value, create, timeout=30):

    conninfo = ConnectionInfo(
        host, port, user, domain, password, ntlm, timeout=timeout
    )

    try:
        with conninfo:
            iWbemServices = conninfo.create_wbem('//./root/cimv2')
            regprov, _ = iWbemServices.GetObject('StdRegprov')

            k = Key(regprov, path)
            try:
                old_value = k[name]
                if old_value.type in (REG_DWORD, REG_DWORD_LITTLE_ENDIAN):
                    if not isinstance(value, (int, long)):
                        value = int(value)
            except KeyError:
                pass

            k[name] = value
            return True

    except KeyError:
        return False


def get(
    host, port,
    user, domain,
    password, ntlm,
        path, name, timeout=30):

    conninfo = ConnectionInfo(
        host, port, user, domain, password, ntlm, timeout=timeout
    )

    try:
        with conninfo:
            iWbemServices = conninfo.create_wbem('//./root/cimv2')
            regprov, _ = iWbemServices.GetObject('StdRegprov')

            return Key(regprov, path)[name].value
    except KeyError:
        return None


def rm(
    host, port,
    user, domain,
    password, ntlm,
        path, name, timeout=30):

    conninfo = ConnectionInfo(
        host, port, user, domain, password, ntlm, timeout=timeout
    )

    try:
        with conninfo:
            iWbemServices = conninfo.create_wbem('//./root/cimv2')
            regprov, _ = iWbemServices.GetObject('StdRegprov')

            del Key(regprov, path)[name]
            return True

    except KeyError:
        return False
