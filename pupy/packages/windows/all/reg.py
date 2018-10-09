# -*- coding: utf-8 -*-

__all__ = [
  'Key', 'search', 'enum',
  'set', 'get', 'rm'
]

import _winreg
import re
import sys

WELL_KNOWN_KEYS = {
    'HKEY_LOCAL_MACHINE': _winreg.HKEY_LOCAL_MACHINE,
    'HKLM': _winreg.HKEY_LOCAL_MACHINE,
    'HKEY_CURRENT_USER': _winreg.HKEY_CURRENT_USER,
    'HKCU': _winreg.HKEY_CURRENT_USER,
    'HKEY_CURRENT_CONFIG': _winreg.HKEY_CURRENT_CONFIG,
    'HKCC': _winreg.HKEY_CURRENT_CONFIG,
    'HKEY_CLASSES_ROOT': _winreg.HKEY_CLASSES_ROOT,
    'HKCR': _winreg.HKEY_CLASSES_ROOT,
    'HKEY_USERS': _winreg.HKEY_USERS,
    'HKU': _winreg.HKEY_USERS,
    'HKEY_PERFORMANCE_DATA': _winreg.HKEY_PERFORMANCE_DATA,
    'HKPD': _winreg.HKEY_PERFORMANCE_DATA,
}

WELL_KNOWN_TYPES = {
    int: _winreg.REG_DWORD,
    str: _winreg.REG_SZ,
    unicode: _winreg.REG_SZ,
}

WELL_KNOWN_TYPES_NAMES = {
    _winreg.REG_DWORD: 'DWORD',
    _winreg.REG_BINARY: 'BINARY',
    _winreg.REG_DWORD_LITTLE_ENDIAN: 'LE32',
    _winreg.REG_DWORD_BIG_ENDIAN: 'BE32',
    _winreg.REG_EXPAND_SZ: 'EXPAND_SZ',
    _winreg.REG_LINK: 'LINK',
    _winreg.REG_MULTI_SZ: 'MULTI_SZ',
    _winreg.REG_NONE: 'NONE',
    _winreg.REG_RESOURCE_LIST: 'RESOURCE',
    _winreg.REG_FULL_RESOURCE_DESCRIPTOR: 'RESOURCE_DESCRIPTOR',
    _winreg.REG_RESOURCE_REQUIREMENTS_LIST: 'RESOURCE_REQUIREMENTS_LIST',
    _winreg.REG_SZ: 'SZ'
}

class KeyIter(object):
    __slots__ = ('handle', 'orig_name', 'key', 'sub', 'idx', 'is_value')

    def __init__(self, orig_name, key, sub, handle):
        self.orig_name = orig_name
        self.key = key
        self.sub = sub
        self.handle = handle
        self.idx = 0
        self.is_value = False

    def next(self):
        try:
            result = None
            if self.is_value:
                name, value, ktype = _winreg.EnumValue(self.handle, self.idx)
                result = Value(self.orig_name, name, value, ktype)
            else:
                value = _winreg.EnumKey(self.handle, self.idx)
                value = value.decode(sys.getfilesystemencoding())
                result = Key(self.orig_name + '\\' + value)

            self.idx += 1
            return result

        except WindowsError, e:
            if e.winerror != 259:
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
        if type(parent) == str:
            parent = parent.decode(sys.getfilesystemencoding())

        if type(name) == str:
            name = name.decode(sys.getfilesystemencoding())

        if type(value) == str and ktype in (_winreg.REG_SZ, _winreg.REG_MULTI_SZ):
            value = value.decode(sys.getfilesystemencoding())

        self.parent = parent
        self.name = name
        self.value = value
        self.type = ktype

    def __str__(self):
        if self.type == _winreg.REG_EXPAND_SZ:
            value = self.value
            if type(value) is not unicode:
                try:
                    value = value.decode(sys.getfilesystemencoding())
                except UnicodeDecodeError:
                    value = value.decode('latin1')

            try:
                return _winreg.ExpandEnvironmentStrings(value)
            except TypeError:
                pass

            return value

        elif self.type == _winreg.REG_SZ:
            return self.value

        return str(self.value)

    def __int__(self):
        return int(self.value)

    def __repr__(self):
        return '{}={} ({})'.format(
            self.name, self.value, WELL_KNOWN_TYPES_NAMES[self.type])

class Key(object):
    __slots__ = ('arg', 'key', 'sub', 'access', 'create')

    def __init__(self, key, access=_winreg.KEY_READ, create=False):
        sub_key = None
        top_key = None

        if type(key) == str:
            key = key.decode(sys.getfilesystemencoding())

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
        return '\\'.join(self.arg.split('\\')[:-1])

    def _open_key(self, access=None):
        try:
            sub = self.sub

            if type(sub) == unicode:
                sub = sub.encode(sys.getfilesystemencoding())

            if self.create:
                return _winreg.CreateKey(
                    self.key, sub)
            else:
                return _winreg.OpenKey(
                    self.key, sub, 0,
                    access if access is not None else self.access)
        except WindowsError, e:
            if e.winerror != 2:
                raise

            raise KeyError(self.sub)

    def _query_value(self, handle, attr):
        try:
            if type(attr) == unicode:
                attr = attr.encode(sys.getfilesystemencoding())
            value, ktype = _winreg.QueryValueEx(handle, attr)
        except WindowsError, e:
            if e.winerror != 2:
                raise

            raise KeyError(attr)

        return Value(self.arg, attr, value, ktype)

    def __iter__(self):
        handle = self._open_key(
            _winreg.KEY_QUERY_VALUE | _winreg.KEY_ENUMERATE_SUB_KEYS)

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
            _winreg.CloseKey(handle)

    def __str__(self):
        return self.arg.encode(sys.getfilesystemencoding())

    def __unicode__(self):
        return self.arg

    def __repr__(self):
        return self.arg

    def __delitem__(self, attr):
        handle = self._open_key(_winreg.KEY_SET_VALUE)

        if type(attr) == unicode:
            attr = attr.encode(sys.getfilesystemencoding())

        try:
            try:
                return _winreg.DeleteValue(handle, attr)
            except WindowsError, e:
                if e.winerror != 2:
                    raise

            try:
                return _winreg.DeleteKey(handle, attr)
            except WindowsError, e:
                if e.winerror != 2:
                    raise

            raise KeyError(attr)

        finally:
            _winreg.CloseKey(handle)

    def __getitem__(self, attr):
        handle = self._open_key()
        try:
            return self._query_value(handle, attr)
        finally:
            _winreg.CloseKey(handle)

    def __setitem__(self, attr, value):
        vtype = type(value)

        if vtype not in WELL_KNOWN_TYPES and vtype is not Value:
            raise TypeError('setattr only supported for str/int')

        ktype = value.type if vtype is Value else WELL_KNOWN_TYPES[vtype]
        if vtype is Value:
            value = value.value

        handle = self._open_key(_winreg.KEY_SET_VALUE)

        if type(attr) == unicode:
            attr = attr.encode(sys.getfilesystemencoding())

        if type(value) == unicode:
            value = value.encode(sys.getfilesystemencoding())

        try:
            return _winreg.SetValueEx(
                handle, attr, 0, ktype, value)
        finally:
            _winreg.CloseKey(handle)

def search(term, roots=('HKU', 'HKLM', 'HKCC'), key=True, name=True, value=True, regex=False, ignorecase=False, first=False, equals=False):
    compare = None

    def as_str(x):
        vtype = type(x)
        if vtype == str:
            return x
        elif vtype == unicode:
            return x.encode('utf-8')
        else:
            return str(x)

    def contains(x, y):
        try:
            if type(x) == str and type(y) == unicode:
                return x in y.encode(sys.getfilesystemencoding())
            elif type(x) == unicode and type(y) == str:
                return x.encode(sys.getfilesystemencoding()) in y.encode
            else:
                return x in y

        except Exception:
            return False

    if regex:
        term = re.compile(
            term,
            re.MULTILINE | (re.IGNORECASE if ignorecase else 0))

        if equals:
            compare = lambda x: term.match(as_str(x))
        else:
            compare = lambda x: term.search(as_str(x))
    elif ignorecase:
        if equals:
            compare = lambda x: as_str(term).lower() == as_str(x).lower()
        else:
            compare = lambda x: as_str(term).lower() in as_str(x).lower()
    else:
        if equals:
            compare = lambda x: term == x
        else:
            compare = lambda x: contains(term, x)

    if type(roots) in (str, unicode):
        roots = [roots]

    def _walk(root):
        results = []

        for kv in root:
            tkv = type(kv)

            if tkv == Key:
                if key and compare(kv.name):
                    results.append(kv)
                    if first and results:
                        break

                try:
                    results.extend(_walk(kv))

                    if first and results:
                        break

                except WindowsError:
                    pass

            elif tkv == Value:
                if name and compare(kv.name):
                    results.append(kv)

                elif value and (equals or type(kv.value) in (str, unicode)) and compare(kv.value):
                    results.append(kv)

                if first and results:
                    break

            else:
                raise TypeError('Unknown type {} in search'.format(tkv.__name__))

        return results

    typleized = []
    for root in roots:
        for result in _walk(Key(root)):
            if type(result) == Key:
                typleized.append((True, str(result)))
            else:
                typleized.append((
                    False, result.parent, result.name,
                    result.value, result.type))

    return typleized

def enum(path):
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
            if old_value.type in (_winreg.REG_SZ, _winreg.REG_BINARY):
                if type(value) not in (str, unicode):
                    value = str(value)
            elif old_value.type in (_winreg.REG_DWORD, _winreg.REG_DWORD_LITTLE_ENDIAN):
                if type(value) != int:
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
