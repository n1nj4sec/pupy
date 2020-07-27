# -*- coding: utf-8 -*-

from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

from sys import (
    getfilesystemencoding, version_info, platform
)

import locale
import unicodedata
import json
import codecs

textchars = bytearray(
    {7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7f}
)

TRY_ENCODINGS = (
    'utf-8', 'utf-16le',
    locale.getpreferredencoding(),
    getfilesystemencoding()
)

DEFAULT_MB_ENCODING = 'utf-8'


if version_info.major > 2:
    import shlex

    def reprb(value):
        return repr(value)

    def as_native_string(
        value, fail=True, encoding=DEFAULT_MB_ENCODING,
            internal_encoding=None):

        # internal_encoding -- ignored
        # In Py3 strings are in unicode

        if isinstance(value, str):
            return value

        elif isinstance(value, bytes):
            return value.decode(encoding)

        elif fail == 'convert':
            if value is None:
                return ''
            else:
                return str(value)

        elif not fail:
            return value

        raise TypeError(
            'Invalid value type {}: {}'.format(
                repr(value), type(value)
            )
        )

    def as_unicode_string(value, encoding=DEFAULT_MB_ENCODING, fail=True):
        if isinstance(value, str):
            return value

        elif isinstance(value, bytes):
            try:
                return value.decode(encoding)
            except UnicodeDecodeError:
                if fail is True:
                    raise
                else:
                    return value

        elif fail == 'convert':
            if value is None:
                return ''
            else:
                return str(value)

        elif not fail:
            return value

        raise TypeError(
            'Invalid value type {}: {}'.format(
                repr(value), type(value)
            )
        )

    def as_unicode_string_deep(value, encoding=DEFAULT_MB_ENCODING, fail=True):
        if isinstance(value, (bytes, str)):
            return as_unicode_string(value, encoding, fail)

        elif isinstance(value, dict):
            vtype = type(value)
            return vtype(
                (
                    as_unicode_string_deep(key, encoding, fail),
                    as_unicode_string_deep(value, encoding, fail)
                ) for key, value in value.items()
            )

        elif isinstance(value, (list, tuple, set, frozenset)):
            vtype = type(value)
            items = (
                as_unicode_string_deep(item, encoding, fail) for item in value
            )

            if hasattr(vtype, '_fields'):
                return vtype(*tuple(items))
            else:
                return vtype(items)

        elif fail == 'convert':
            if value is None:
                return ''
            else:
                return str(value)

        return value

    def as_escaped_string(value, fail=True):
        if isinstance(value, bytes):
            value = try_as_unicode_string(value, fail)

        if isinstance(value, bytes):
            # Fail = false, conv failed
            return value
        elif isinstance(value, str):
            return value.encode('unicode-escape')
        elif fail == 'convert':
            if value is None:
                return ''
            else:
                return str(value).encode('unicode-escape')
        elif fail:
            raise TypeError(type(value))
        else:
            return value

    def filter_strings(values):
        for value in values:
            if isinstance(value, str):
                yield value

else:
    import ushlex as shlex

    def reprb(value):
        return 'b' + repr(value)

    def as_native_string(
        value, fail=True, encoding=DEFAULT_MB_ENCODING,
            internal_encoding=DEFAULT_MB_ENCODING):

        if isinstance(value, str):
            if encoding == internal_encoding:
                return value

            try:
                return value.decode(encoding).encode(internal_encoding)
            except UnicodeError:
                if not fail:
                    return value
                else:
                    raise

        elif isinstance(value, unicode):
            return value.encode(internal_encoding)

        elif fail == 'convert':
            if value is None:
                return str('')
            else:
                return str(value)

        elif not fail:
            return value

        raise TypeError(
            'Invalid value type {}: {}'.format(
                repr(value), type(value)
            )
        )

    def as_unicode_string(value, encoding=DEFAULT_MB_ENCODING, fail=True):
        if isinstance(value, unicode):
            return value

        elif isinstance(value, bytes):
            try:
                return value.decode(encoding)
            except UnicodeDecodeError:
                if fail:
                    raise
                else:
                    return value

        elif fail == 'convert':
            if value is None:
                return unicode('')
            else:
                return unicode(value)

        elif not fail:
            return value

        raise TypeError(
            'Invalid value type {}: {}'.format(
                repr(value), type(value)
            )
        )

    def as_unicode_string_deep(
            value, encoding=DEFAULT_MB_ENCODING, fail=True):
        if isinstance(value, (bytes, unicode)):
            return as_unicode_string(value, encoding, fail)

        elif isinstance(value, dict):
            vtype = type(value)
            return vtype(
                (
                    as_unicode_string_deep(key, encoding, fail),
                    as_unicode_string_deep(value, encoding, fail)
                ) for key, value in value.items()
            )

        elif isinstance(value, (list, tuple, set, frozenset)):
            vtype = type(value)
            items = (
                as_unicode_string_deep(item, encoding, fail) for item in value
            )

            if hasattr(vtype, '_fields'):
                return vtype(*tuple(items))
            else:
                return vtype(items)

        elif fail == 'convert':
            if value is None:
                return ''
            else:
                return unicode(value)

        return value

    def as_escaped_string(value, fail=True):
        if isinstance(value, bytes):
            value = try_as_unicode_string(value, fail)

        if isinstance(value, bytes):
            # Fail = false, conv failed
            return value
        elif isinstance(value, unicode):
            return value.encode('unicode-escape')
        elif fail == 'convert':
            if value is None:
                return str('')
            else:
                return str(value).encode('string-escape')
        elif fail:
            raise TypeError(type(value))
        else:
            return value

    def filter_strings(values):
        for value in values:
            if isinstance(value, basestring):
                yield value


class ExtendedJsonEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return 'hex:' + codecs.encode(obj, 'hex').decode('ascii')
        else:
            return super(ExtendedJsonEncoder, self).default(obj)


class ExtendedJsonDecoder(json.JSONDecoder):
    def __init__(self, *args, **kwargs):
        json.JSONDecoder.__init__(
            self, object_hook=self._hook, *args, **kwargs
        )

    def _hook(self, obj):
        if not isinstance(obj, str):
            return obj

        if obj.startswith('hex:'):
            return codecs.decode(obj[4:], 'hex')


def fs_as_unicode_string(value, fail=True):
    return as_unicode_string(
        value,
        encoding=getfilesystemencoding(),
        fail=fail
    )


def fs_as_unicode_string_deep(value):
    return as_unicode_string_deep(
        value,
        encoding=getfilesystemencoding()
    )


def fs_as_native_string(value):
    return as_native_string(
        value,
        encoding=getfilesystemencoding()
    )


def try_as_native_string(value, fail=True):
    for encoding in TRY_ENCODINGS:
        try:
            return as_native_string(
                value, fail=True, encoding=encoding
            )
        except UnicodeError:
            pass

    if fail:
        raise UnicodeError('Unknown encoding')

    return value


def try_as_unicode_string(value, fail=True):
    for encoding in TRY_ENCODINGS:
        try:
            return as_unicode_string(
                value, fail=fail, encoding=encoding
            )
        except UnicodeError:
            pass

    if fail:
        raise UnicodeError('Unknown encoding')

    return value


def fix_exception_encoding(exc):
    exc.args = tuple(
        try_as_native_string(arg, fail=False) for arg in exc.args
    )

    if hasattr(exc, 'message'):
        exc.message = try_as_native_string(exc.message, fail=False)

    return exc


def is_binary(text):
    if isinstance(text, bytes):
        for byte in text:
            if byte not in textchars:
                return True

        return False
    else:
        for char in text:
            if char in '\r\n\t':
                continue

            if unicodedata.category(char) == 'Cc':
                return True

        return False
