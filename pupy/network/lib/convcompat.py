# -*- coding: utf-8 -*-

from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

from sys import (
    getdefaultencoding, getfilesystemencoding, version_info
)


if version_info.major > 2:
    def as_attr_type(value, fail=True):
        if isinstance(value, str):
            return value

        elif isinstance(value, bytes):
            return value.decode('utf-8')

        elif not fail:
            return value

        raise TypeError(
            'Invalid attribute type {}: {}'.format(
                type(value), repr(value)
            )
        )

    def unicodify(value, encoding=getdefaultencoding()):
        if isinstance(value, str):
            return value

        elif isinstance(value, bytes):
            return value.decode(encoding)

        elif isinstance(value, dict):
            vtype = type(value)
            return vtype(
                (unicodify(key, encoding), unicodify(value, encoding))
                for key, value in value.items()
            )

        elif isinstance(value, (list, tuple, set, frozenset)):
            vtype = type(value)
            items = (
                unicodify(item, encoding) for item in value
            )

            if hasattr(vtype, '_fields'):
                return vtype(*tuple(items))
            else:
                return vtype(items)

        return value

else:
    def as_attr_type(value, fail=True):
        if isinstance(value, str):
            return value

        elif isinstance(value, unicode):
            return value.encode('utf-8')

        elif not fail:
            return value

        raise TypeError(
            'Invalid attribute type {}: {}'.format(
                type(value), repr(value)
            )
        )

    def unicodify(value, encoding=getdefaultencoding()):
        if isinstance(value, unicode):
            return value

        elif isinstance(value, bytes):
            return value.decode(encoding)

        elif isinstance(value, dict):
            vtype = type(value)
            return vtype(
                (unicodify(key, encoding), unicodify(value, encoding))
                for key, value in value.items()
            )

        elif isinstance(value, (list, tuple, set, frozenset)):
            vtype = type(value)
            items = (
                unicodify(item, encoding) for item in value
            )

            if hasattr(vtype, '_fields'):
                return vtype(*tuple(items))
            else:
                return vtype(items)

        return value


def fsunicodify(value):
    return unicodify(value, getfilesystemencoding())
