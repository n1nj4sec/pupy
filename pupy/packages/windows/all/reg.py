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

from ctypes import (
    POINTER, byref,
    c_char_p, c_void_p, c_long,
    c_ulonglong, Structure, WinError, WinDLL,
    create_unicode_buffer, create_string_buffer,
    wstring_at
)

from ctypes.wintypes import (
    DWORD, LPCWSTR
)


class FILETIME(Structure):
    _fields_ = [
        ('dwLowDateTime', DWORD),
        ('dwHighDateTime', DWORD)
    ]


HKEY = c_ulonglong
PHKEY = POINTER(HKEY)
PFILETIME = POINTER(FILETIME)
PDWORD = POINTER(DWORD)
LPDWORD = PDWORD
LPBYTE = c_char_p
REGSAM = DWORD

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

advapi32 = WinDLL('advapi32', use_last_error=True)

RegOpenKeyEx = advapi32.RegOpenKeyExW
RegOpenKeyEx.restype = c_long
RegOpenKeyEx.argtypes = (
    HKEY, LPCWSTR, DWORD, REGSAM, PHKEY
)

RegCreateKeyEx = advapi32.RegCreateKeyExW
RegCreateKeyEx.restype = c_long
RegCreateKeyEx.argtypes = (
    HKEY, LPCWSTR, DWORD,
    LPCWSTR, DWORD, REGSAM,
    c_void_p, PHKEY, LPDWORD
)

RegQueryInfoKey = advapi32.RegQueryInfoKeyW
RegQueryInfoKey.restype = c_long
RegQueryInfoKey.argtypes = (
    HKEY, LPCWSTR, LPDWORD, LPDWORD,
    PDWORD, LPDWORD, LPDWORD, LPDWORD,
    LPDWORD, LPDWORD, LPDWORD,
    PFILETIME
)

RegEnumValue = advapi32.RegEnumValueW
RegEnumValue.restype = c_long
RegEnumValue.argtypes = (
    HKEY, DWORD, LPCWSTR, LPDWORD,
    LPDWORD, LPDWORD, LPBYTE, LPDWORD
)

RegEnumKeyEx = advapi32.RegEnumKeyExW
RegEnumKeyEx.restype = c_long
RegEnumKeyEx.argtypes = (
    HKEY, DWORD, LPCWSTR, LPDWORD,
    LPDWORD, LPCWSTR, LPDWORD,
    PFILETIME
)

RegQueryValueEx = advapi32.RegQueryValueExW
RegQueryValueEx.restype = c_long
RegQueryValueEx.argtypes = (
    HKEY, LPCWSTR, LPDWORD, LPDWORD,
    LPBYTE, LPDWORD
)

RegSetValueEx = advapi32.RegSetValueExW
RegSetValueEx.restype = c_long
RegSetValueEx.argtypes = (
    HKEY, LPCWSTR, DWORD, DWORD,
    LPBYTE, DWORD
)

RegCloseKey = advapi32.RegCloseKey
RegCloseKey.restype = c_long
RegCloseKey.argtypes = (
    HKEY,
)

RegDeleteValue = advapi32.RegDeleteValueW
RegDeleteValue.restype = c_long
RegDeleteValue.argtypes = (HKEY, LPCWSTR)

RegDeleteKey = advapi32.RegDeleteValueW
RegDeleteKey.restype = c_long
RegDeleteKey.argtypes = (HKEY, LPCWSTR)


HKEY_CLASSES_ROOT = HKEY(0x80000000)
HKEY_CURRENT_USER = HKEY(0x80000001)
HKEY_LOCAL_MACHINE = HKEY(0x80000002)
HKEY_USERS = HKEY(0x80000003)
HKEY_PERFORMANCE_DATA = HKEY(0x80000004)
HKEY_CURRENT_CONFIG = HKEY(0x80000005)
HKEY_DYN_DATA = HKEY(0x80000006)

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


def raise_on_error(code):
    if code == ERROR_SUCCESS:
        return

    raise WinError(code)


def QueryValueEx(key, value_name):
    typ = DWORD()
    size = DWORD(0)

    value_name = as_unicode(value_name)

    rc = RegQueryValueEx(
        key, value_name, None,
        byref(typ),
        None, byref(size)
    )

    if rc != ERROR_MORE_DATA:
        raise_on_error(rc)

    buf = create_string_buffer(size.value)
    rc = RegQueryValueEx(
        key, value_name, None,
        byref(typ),
        buf, byref(size)
    )

    raise_on_error(rc)
    return buf[:size.value], typ.value


def EnumValue(key, index, max_value_size=None, max_data_size=None):
    if max_data_size is None or max_value_size is None:
        value_size = DWORD(0)
        data_size = DWORD(0)

        rc = RegQueryInfoKey(
            key, None, None, None, None,
            None, None, None,
            byref(value_size), byref(data_size),
            None, None
        )

        raise_on_error(rc)

        value_size.value += 1

        value = create_unicode_buffer(value_size.value)
        data = create_string_buffer(data_size.value)
    else:
        value_size = DWORD(max_value_size)
        data_size = DWORD(max_data_size)

        value = create_unicode_buffer(value_size.value)
        data = create_string_buffer(data_size.value)

    typ = DWORD()
    rc = RegEnumValue(
        key, index,
        value, byref(value_size),
        None, byref(typ),
        data, byref(data_size)
    )

    raise_on_error(rc)
    return value.value, data[:data_size.value], typ.value


def EnumKey(key, index):
    tmpbuf = create_unicode_buffer(257)
    length = DWORD(257)

    rc = RegEnumKeyEx(
        key, index,
        tmpbuf,
        byref(length), None,
        None, None, None
    )

    raise_on_error(rc)
    return wstring_at(tmpbuf, length.value).rstrip(u'\x00')


def OpenKey(key, sub_key, access=KEY_READ, options=REG_OPTION_RESERVED):
    sub_key = as_unicode(sub_key)

    new_key = HKEY()
    rc = RegOpenKeyEx(
        key, sub_key,
        options,
        access,
        byref(new_key)
    )

    raise_on_error(rc)
    return new_key


def CreateKey(key, sub_key, access=KEY_WRITE, options=REG_OPTION_RESERVED):
    sub_key = as_unicode(sub_key)
    new_key = HKEY()
    rc = RegCreateKeyEx(
        key, sub_key, 0, None, options, access,
        None, byref(new_key), None
    )

    raise_on_error(rc)
    return new_key


def SetValueEx(key, name, ktype, value):
    value = value_to_bytes(value, ktype)
    name = as_unicode(name)
    size = len(value)

    rc = RegSetValueEx(
        key, name, 0, ktype, value, size
    )
    raise_on_error(rc)


def DeleteKey(key, subkey):
    subkey = as_unicode(subkey)
    rc = RegDeleteKey(key, subkey)
    raise_on_error(rc)


def DeleteValue(key, value):
    value = as_unicode(value)
    rc = RegDeleteValue(key, value)
    raise_on_error(rc)


def CloseKey(key):
    rc = RegCloseKey(key)
    raise_on_error(rc)


class KeyIter(object):
    __slots__ = (
        'handle', 'orig_name', 'key',
        'sub', 'idx', 'is_value',
        'max_value_size', 'max_data_size'
    )

    def __init__(self, orig_name, key, sub, handle):
        self.orig_name = orig_name
        self.key = key
        self.sub = sub
        self.handle = handle
        self.idx = 0
        self.is_value = False
        self.max_value_size = None
        self.max_data_size = None

    def next(self):
        try:
            result = None
            if self.is_value:
                if self.max_value_size is None or self.max_data_size is None:
                    value_size = DWORD(0)
                    data_size = DWORD(0)

                    rc = RegQueryInfoKey(
                        self.handle, None, None, None, None,
                        None, None, None,
                        byref(value_size), byref(data_size),
                        None, None
                    )

                    raise_on_error(rc)

                    self.max_value_size = value_size.value + 2
                    self.max_data_size = data_size.value

                name, value, ktype = EnumValue(
                    self.handle, self.idx,
                    self.max_value_size, self.max_data_size
                )
                result = Value(self.orig_name, name, value, ktype)
            else:
                value = EnumKey(self.handle, self.idx)
                result = Key(u'\\'.join([self.orig_name, value]))

            self.idx += 1
            return result

        except WindowsError as e:
            if e.winerror != 259:
                self.idx += 1
                raise

            if self.is_value:
                raise StopIteration()
            else:
                self.idx = 0
                self.is_value = True
                return self.next()

class Value(object):
    __slots__ = ('parent', 'name', 'value', 'type')

    def __init__(self, parent, name, value, ktype):
        parent = as_unicode(parent)
        name = as_unicode(name)

        if len(value) < 5 and all(x == '\0' for x in value):
            value = ''

        if isinstance(value, str):
            if ktype in (REG_SZ, REG_EXPAND_SZ):
                try:
                    value = value.decode('utf-16le')
                except UnicodeError:
                    try:
                        value = value.decode('mbcs')
                    except UnicodeError:
                        raise ValueError('{}: {}'.format(repr(value), len(value)))
                value = value.rstrip('\0')

            elif ktype == REG_MULTI_SZ:
                values = []

                while value:
                    try:
                        last_zero = value.index('\0\0')
                        record = value[:last_zero]
                        record = record.decode('utf-16le')
                        values.append(record)
                        value = value[last_zero+1:]
                    except ValueError:
                        break

                if value:
                    values.append(value)

                value = values

            elif ktype == REG_DWORD:
                if len(value):
                    value, = struct.unpack('<i', value)
                else:
                    value = 0

            elif ktype == REG_DWORD_LITTLE_ENDIAN:
                if len(value):
                    value, = struct.unpack('<i', value)
                else:
                    value = 0

            elif ktype == REG_DWORD_BIG_ENDIAN:
                if len(value):
                    value, = struct.unpack('>i', value)
                else:
                    value = 0

            elif ktype == REG_QWORD:
                if len(value):
                    value, = struct.unpack('<q', value)
                else:
                    value = 0

        self.parent = parent
        self.name = name
        self.value = value
        self.type = ktype

    @property
    def raw(self):
        return value_to_bytes(self.value, self.type)

    def __str__(self):
        return as_str(self.value)

    def __int__(self):
        return int(self.value)

    def __repr__(self):
        return 'Value({}, {}, {}, {})'.format(
            repr(self.parent),
            repr(self.name),
            repr(self.value),
            repr(self.type)
        )

class Key(object):
    __slots__ = ('arg', 'key', 'sub', 'access', 'create')

    def __init__(self, key, access=KEY_READ, create=False):
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
        self.access = access
        self.create = create

    @property
    def name(self):
        return self.arg.split('\\')[-1]

    @property
    def parent(self):
        return u'\\'.join(self.arg.split('\\')[:-1])

    def _open_key(self, access=KEY_READ):
        if access is None:
            access = self.access
        try:
            if self.create:
                return CreateKey(self.key, self.sub, access)
            else:
                return OpenKey(self.key, self.sub, access)

        except WindowsError as e:
            if e.winerror != 2:
                raise

            raise KeyError(self.sub)

    def _query_value(self, handle, attr):
        attr = as_unicode(attr)
        try:
            value, ktype = QueryValueEx(handle, attr)
        except WindowsError, e:
            if e.winerror != 2:
                raise

            raise KeyError(attr)

        return Value(self.arg, attr, value, ktype)

    def __iter__(self):
        handle = self._open_key(
            KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS)

        iterator = KeyIter(self.arg, self.key, self.sub, handle)
        try:
            while True:
                try:
                    yield next(iterator)
                except WindowsError:
                    pass

        except StopIteration:
            return

        finally:
            CloseKey(handle)

    def __str__(self):
        return as_str(self.arg)

    def __unicode__(self):
        return as_unicode(self.arg)

    def __repr__(self):
        return repr(self.arg)

    def __int__(self):
        return repr(self.arg)

    def __delitem__(self, attr):
        handle = self._open_key(KEY_SET_VALUE)

        try:
            try:
                return DeleteValue(handle, attr)
            except WindowsError as e:
                if e.winerror != 2:
                    raise

            try:
                return DeleteKey(handle, attr)
            except WindowsError as e:
                if e.winerror != 2:
                    raise

            raise KeyError(attr)

        finally:
            CloseKey(handle)

    def __getitem__(self, attr):
        handle = self._open_key(KEY_QUERY_VALUE)
        try:
            return self._query_value(handle, attr)
        finally:
            CloseKey(handle)

    def __setitem__(self, attr, value):
        vtype = type(value)

        if vtype not in WELL_KNOWN_TYPES and vtype is not Value:
            raise TypeError('setattr only supported for str/int')

        ktype = value.type if vtype is Value else WELL_KNOWN_TYPES[vtype]
        if vtype is Value:
            value = value.value
        elif ktype == REG_SZ and '%' in value:
            ktype = REG_EXPAND_SZ

        handle = self._open_key(KEY_ALL_ACCESS)
        try:
            return SetValueEx(
                handle, attr, ktype, value
            )
        finally:
            CloseKey(handle)

def _search(
    completed, data_cb, close_cb,
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
        for kv in root:
            if completed.is_set():
                break

            if isinstance(kv, Key):
                if key and compare(kv.name):
                    data_cb((True, kv.name))
                    if first:
                        completed.set()
                        return

                try:
                    _walk(kv, data_cb)
                except WindowsError:
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
                _walk(Key(root), data_cb)
            except WindowsError:
                continue

    except Exception as e:
        data_cb((None, '{}\n{}'.format(e, traceback.format_exc())))

    finally:
        if completed.is_set():
            data_cb((None, 'Interrupted'))

        completed.set()
        close_cb()


def search(
    data_cb, close_cb,
    term, roots=('HKU', 'HKLM', 'HKCC'), key=True,
        name=True, value=True, regex=False,
        ignorecase=False, first=False, equals=False):

    data_cb = rpyc.async(data_cb)
    close_cb = rpyc.async(close_cb)

    completed = threading.Event()
    worker = threading.Thread(
        name='Reg:Search',
        target=_search,
        args=(
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


def enum(path=None):
    if path is None:
        return [(
            True, unicode(item)
        ) for item in WELL_KNOWN_KEYS]

    try:
        tupleized = []

        for item in Key(path):
            if type(item) == Key:
                tupleized.append((True, unicode(item)))
            else:
                tupleized.append((
                    False, item.parent, item.name,
                    item.value, item.type))

        return tuple(tupleized)

    except KeyError:
        return None

def set(path, name, value, create):
    try:
        k = Key(path, create=create)
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

def get(path, name):
    try:
        return Key(path)[name].value
    except KeyError:
        return None

def rm(path, name):
    try:
        del Key(path)[name]
        return True
    except KeyError:
        return False
