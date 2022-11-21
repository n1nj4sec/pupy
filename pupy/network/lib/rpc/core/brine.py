"""
**Brine** is a simple, fast and secure object serializer for **immutable** objects.
The following types are supported: ``int``, ``long``, ``bool``, ``str``, ``float``,
``unicode``, ``bytes``, ``slice``, ``complex``, ``tuple`` (of simple types),
``frozenset`` (of simple types) as well as the following singletons: ``None``,
``NotImplemented``, and ``Ellipsis``.

Example::

    >>> x = ("he", 7, u"llo", 8, (), 900, None, True, Ellipsis, 18.2, 18.2j + 13,
    ... slice(1,2,3), frozenset([5,6,7]), NotImplemented)
    >>> dumpable(x)
    True
    >>> y = dump(x)
    >>> y.encode("hex")
    '140e0b686557080c6c6c6f580216033930300003061840323333333333331b402a000000000000403233333333333319125152531a1255565705'
    >>> z = load(y)
    >>> x == z
    True
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import logging

from pupy.network.lib.compat import (
    Struct, BytesIO, is_py3k, as_byte, xrange
)


# singletons
TAG_NONE = b'\x00'
TAG_EMPTY_STR = b'\x01'
TAG_EMPTY_TUPLE = b'\x02'
TAG_TRUE = b'\x03'
TAG_FALSE = b'\x04'
TAG_NOT_IMPLEMENTED = b'\x05'
TAG_ELLIPSIS = b'\x06'
# types
TAG_UNICODE = b'\x08'
TAG_LONG = b'\x09'
TAG_STR1 = b'\x0a'
TAG_STR2 = b'\x0b'
TAG_STR3 = b'\x0c'
TAG_STR4 = b'\x0d'
TAG_STR_L1 = b'\x0e'
TAG_STR_L4 = b'\x0f'
TAG_TUP1 = b'\x10'
TAG_TUP2 = b'\x11'
TAG_TUP3 = b'\x12'
TAG_TUP4 = b'\x13'
TAG_TUP_L1 = b'\x14'
TAG_TUP_L4 = b'\x15'
TAG_INT_L1 = b'\x16'
TAG_INT_L4 = b'\x17'
TAG_FLOAT = b'\x18'
TAG_SLICE = b'\x19'
TAG_FSET = b'\x1a'
TAG_COMPLEX = b'\x1b'

# non-standard pupy RPC extensions
TAG_NAMED_TUPLE = b'\xf0'
TAG_IMMUTABLE_DICT = b'\xf1'
TAG_IMMUTABLE_SET = b'\xf2'
TAG_IMMUTABLE_LIST = b'\xf2'

REGISTERED_NAMED_TUPLES_PACK = {}
REGISTERED_NAMED_TUPLES_UNPACK = {}

MAX_REGISTERED_VERSION = 1


I1 = Struct(">B")
I4 = Struct(">L")
F8 = Struct(">d")
C16 = Struct(">dd")

_dump_registry = tuple(
    dict() for _ in xrange(MAX_REGISTERED_VERSION + 1)
)

_load_registry = tuple(
    ([None]*256) for _ in xrange(MAX_REGISTERED_VERSION + 1)
)


def _dump_named_tuple(obj, stream, version):
    obj_type = type(obj)
    tuple_id = REGISTERED_NAMED_TUPLES_PACK.get(obj_type)

    if tuple_id is None:
        raise ValueError('Unregistered named tuple type %s', obj_type)

    stream.append(TAG_NAMED_TUPLE)
    stream.append(I4.pack(tuple_id))
    tuple_dump = _dump_registry[0][tuple]
    tuple_dump(obj, stream, version)


def register_named_tuple(code, ntype):
    REGISTERED_NAMED_TUPLES_PACK[ntype] = code
    REGISTERED_NAMED_TUPLES_UNPACK[code] = ntype

    for ver in xrange(1, MAX_REGISTERED_VERSION + 1):
        _dump_registry[ver][ntype] = _dump_named_tuple


def register(coll, key, min_version=0):
    def deco(func):
        for version in xrange(min_version, MAX_REGISTERED_VERSION + 1):
            if coll is _dump_registry:
                _dump_registry[version][key] = func

            elif coll is _load_registry:
                _load_registry[version][ord(key)] = func

            else:
                raise ValueError(
                    'Unknown registry %s' % (repr(coll),)
                )

        return func

    return deco

# =============================================================================
# dumping
# =============================================================================


@register(_dump_registry, type(None))
def _dump_none(obj, stream, version):
    stream.append(TAG_NONE)


@register(_dump_registry, type(NotImplemented))
def _dump_notimplemeted(obj, stream, version):
    stream.append(TAG_NOT_IMPLEMENTED)


@register(_dump_registry, type(Ellipsis))
def _dump_ellipsis(obj, stream, version):
    stream.append(TAG_ELLIPSIS)


@register(_dump_registry, bool)
def _dump_bool(obj, stream, version):
    if obj:
        stream.append(TAG_TRUE)
    else:
        stream.append(TAG_FALSE)


@register(_dump_registry, slice)
def _dump_slice(obj, stream, version):
    stream.append(TAG_SLICE)
    _dump((obj.start, obj.stop, obj.step), stream, version)


@register(_dump_registry, frozenset)
def _dump_frozenset(obj, stream, version):
    stream.append(TAG_FSET)
    _dump(tuple(obj), stream, version)


@register(_dump_registry, int)
def _dump_int(obj, stream, version):
    if obj >= -0x30 and obj < 0xa0:
        stream.append(as_byte(obj + 0x50))
    else:
        obj = str(obj).encode('ascii')
        obj_len = len(obj)
        if obj_len < 256:
            stream.append(TAG_INT_L1 + I1.pack(obj_len) + obj)
        else:
            stream.append(TAG_INT_L4 + I4.pack(obj_len) + obj)


@register(_dump_registry, float)
def _dump_float(obj, stream, version):
    stream.append(TAG_FLOAT + F8.pack(obj))


@register(_dump_registry, complex)
def _dump_complex(obj, stream, version):
    stream.append(TAG_COMPLEX + C16.pack(obj.real, obj.imag))


if is_py3k:
    @register(_dump_registry, bytes)
    def _dump_bytes(obj, stream, version):
        obj_len = len(obj)
        if obj_len == 0:
            stream.append(TAG_EMPTY_STR)
        elif obj_len == 1:
            stream.append(TAG_STR1 + obj)
        elif obj_len == 2:
            stream.append(TAG_STR2 + obj)
        elif obj_len == 3:
            stream.append(TAG_STR3 + obj)
        elif obj_len == 4:
            stream.append(TAG_STR4 + obj)
        elif obj_len < 256:
            stream.append(TAG_STR_L1 + I1.pack(obj_len))
            stream.append(obj)
        else:
            stream.append(TAG_STR_L4 + I4.pack(obj_len))
            stream.append(obj)

    @register(_dump_registry, str)
    def _dump_str(obj, stream, version):
        stream.append(TAG_UNICODE)
        _dump_bytes(obj.encode('utf8'), stream, version)

    @register(_dump_registry, dict, 1)
    def _dump_immutable_dict(obj, stream, version):
        stream.append(TAG_IMMUTABLE_DICT)
        items = len(obj)
        stream.append(I4.pack(items))

        for item in obj.items():
            _dump(item, stream, version)

    @register(_dump_registry, type({}.keys()), 1)
    def _dump_immutable_dict_keys(obj, stream, version):
        stream.append(TAG_IMMUTABLE_LIST)
        items = len(obj)
        stream.append(I4.pack(items))

        for item in obj:
            _dump(item, stream, version)

else:
    @register(_dump_registry, str)
    def _dump_str(obj, stream, version):
        obj_len = len(obj)
        if obj_len == 0:
            stream.append(TAG_EMPTY_STR)
        elif obj_len == 1:
            stream.append(TAG_STR1 + obj)
        elif obj_len == 2:
            stream.append(TAG_STR2 + obj)
        elif obj_len == 3:
            stream.append(TAG_STR3 + obj)
        elif obj_len == 4:
            stream.append(TAG_STR4 + obj)
        elif obj_len < 256:
            stream.append(TAG_STR_L1 + I1.pack(obj_len))
            stream.append(obj)
        else:
            stream.append(TAG_STR_L4 + I4.pack(obj_len))
            stream.append(obj)

    @register(_dump_registry, unicode)
    def _dump_unicode(obj, stream, version):
        stream.append(TAG_UNICODE)
        _dump_str(obj.encode('utf8'), stream, version)

    @register(_dump_registry, long)
    def _dump_long(obj, stream, version):
        stream.append(TAG_LONG)
        _dump_int(obj, stream, version)

    @register(_dump_registry, dict, 1)
    def _dump_immutable_dict(obj, stream, version):
        stream.append(TAG_IMMUTABLE_DICT)
        items = len(obj)
        stream.append(I4.pack(items))

        for item in obj.iteritems():
            _dump(item, stream, version)


@register(_dump_registry, set, 1)
def _dump_immutable_set(obj, stream, version):
    stream.append(TAG_IMMUTABLE_SET)
    items = len(obj)
    stream.append(I4.pack(items))

    for item in obj:
        _dump(item, stream, version)


@register(_dump_registry, list, 1)
def _dump_immutable_list(obj, stream, version):
    stream.append(TAG_IMMUTABLE_LIST)
    items = len(obj)
    stream.append(I4.pack(items))

    for item in obj:
        _dump(item, stream, version)


@register(_dump_registry, tuple)
def _dump_tuple(obj, stream, version):
    obj_len = len(obj)
    if obj_len == 0:
        stream.append(TAG_EMPTY_TUPLE)
    elif obj_len == 1:
        stream.append(TAG_TUP1)
    elif obj_len == 2:
        stream.append(TAG_TUP2)
    elif obj_len == 3:
        stream.append(TAG_TUP3)
    elif obj_len == 4:
        stream.append(TAG_TUP4)
    elif obj_len < 256:
        stream.append(TAG_TUP_L1 + I1.pack(obj_len))
    else:
        stream.append(TAG_TUP_L4 + I4.pack(obj_len))

    for item in obj:
        _dump(item, stream, version)


def _undumpable(obj, stream, version):
    raise TypeError("cannot dump %r (%s) version=%s" % (
        obj, type(obj), version)
    )


def _dump(obj, stream, version=0):
    dumper = _dump_registry[version].get(
        type(obj), _undumpable
    )

    dumper(obj, stream, version)

# =============================================================================
# loading
# =============================================================================


@register(_load_registry, TAG_NAMED_TUPLE, 1)
def _load_named_tuple(stream, version):
    tuple_id, = I4.unpack(stream.read(4))
    obj_type = REGISTERED_NAMED_TUPLES_UNPACK.get(tuple_id)
    if obj_type is None:
        raise ValueError('Unregistered named tuple id %s', tuple_id)

    tuple_data = _load(stream, version)
    return obj_type(*tuple_data)


@register(_load_registry, TAG_IMMUTABLE_DICT, 1)
def _load_immutable_dict(stream, version):
    items, = I4.unpack(stream.read(4))
    dict_items = []

    for _ in xrange(items):
        dict_items.append(_load(stream, version))

    return dict(dict_items)


@register(_load_registry, TAG_IMMUTABLE_SET, 1)
def _load_immutable_set(stream, version):
    items, = I4.unpack(stream.read(4))
    result = set()

    for _ in xrange(items):
        result.add(_load(stream, version))

    return result


@register(_load_registry, TAG_IMMUTABLE_LIST, 1)
def _load_immutable_list(stream, version):
    items, = I4.unpack(stream.read(4))
    result = list()

    for _ in xrange(items):
        result.append(_load(stream, version))

    return result


@register(_load_registry, TAG_NONE)
def _load_none(stream, version):
    return None


@register(_load_registry, TAG_NOT_IMPLEMENTED)
def _load_nonimp(stream, version):
    return NotImplemented


@register(_load_registry, TAG_ELLIPSIS)
def _load_elipsis(stream, version):
    return Ellipsis


@register(_load_registry, TAG_TRUE)
def _load_true(stream, version):
    return True


@register(_load_registry, TAG_FALSE)
def _load_false(stream, version):
    return False


@register(_load_registry, TAG_EMPTY_TUPLE)
def _load_empty_tuple(stream, version):
    return ()


@register(_load_registry, TAG_EMPTY_STR)
def _load_empty_str(stream, version):
    return b''


if is_py3k:
    @register(_load_registry, TAG_LONG)
    def _load_long(stream, version):
        obj = _load(stream, version)
        return int(obj)
else:
    @register(_load_registry, TAG_LONG)
    def _load_long(stream, version):
        obj = _load(stream, version)
        return long(obj)


@register(_load_registry, TAG_FLOAT)
def _load_float(stream, version):
    return F8.unpack(stream.read(8))[0]


@register(_load_registry, TAG_COMPLEX)
def _load_complex(stream, version):
    real, imag = C16.unpack(stream.read(16))
    return complex(real, imag)


@register(_load_registry, TAG_STR1)
def _load_str1(stream, version):
    return stream.read(1)


@register(_load_registry, TAG_STR2)
def _load_str2(stream, version):
    return stream.read(2)


@register(_load_registry, TAG_STR3)
def _load_str3(stream, version):
    return stream.read(3)


@register(_load_registry, TAG_STR4)
def _load_str4(stream, version):
    return stream.read(4)


@register(_load_registry, TAG_STR_L1)
def _load_str_l1(stream, version):
    obj_len, = I1.unpack(stream.read(1))
    return stream.read(obj_len)


@register(_load_registry, TAG_STR_L4)
def _load_str_l4(stream, version):
    obj_len, = I4.unpack(stream.read(4))
    return stream.read(obj_len)


@register(_load_registry, TAG_UNICODE)
def _load_unicode(stream, version):
    obj = _load(stream, version)
    return obj.decode("utf-8")


@register(_load_registry, TAG_TUP1)
def _load_tup1(stream, version):
    return (_load(stream, version),)


@register(_load_registry, TAG_TUP2)
def _load_tup2(stream, version):
    return (_load(stream, version), _load(stream, version))


@register(_load_registry, TAG_TUP3)
def _load_tup3(stream, version):
    return (
        _load(stream, version), _load(stream, version),
        _load(stream, version)
    )


@register(_load_registry, TAG_TUP4)
def _load_tup4(stream, version):
    return (
        _load(stream, version), _load(stream, version),
        _load(stream, version), _load(stream, version)
    )


@register(_load_registry, TAG_TUP_L1)
def _load_tup_l1(stream, version):
    obj_len, = I1.unpack(stream.read(1))
    return tuple(_load(stream, version) for _ in xrange(obj_len))


@register(_load_registry, TAG_TUP_L4)
def _load_tup_l4(stream, version):
    obj_len, = I4.unpack(stream.read(4))
    return tuple(_load(stream, version) for _ in xrange(obj_len))


@register(_load_registry, TAG_SLICE)
def _load_slice(stream, version):
    start, stop, step = _load(stream, version)
    return slice(start, stop, step)


@register(_load_registry, TAG_FSET)
def _load_frozenset(stream, version):
    return frozenset(_load(stream, version))


@register(_load_registry, TAG_INT_L1)
def _load_int_l1(stream, version):
    obj_len, = I1.unpack(stream.read(1))
    return int(stream.read(obj_len))


@register(_load_registry, TAG_INT_L4)
def _load_int_l4(stream, version):
    obj_len, = I4.unpack(stream.read(4))
    return int(stream.read(obj_len))


def _load(stream, version=0):
    tag = stream.read(1)
    ival = ord(tag)

    if ival >= 0x20 and ival < 0xf0:
        return ival - 0x50

    loader = _load_registry[version][ival]
    if loader is None:
        raise ValueError('Unknown tag 0x%02x' % (ival,))

    return loader(stream, version)


# =============================================================================
# API
# =============================================================================


def dump(obj, version=0):
    """Converts (dumps) the given object to a byte-string representation

    :param obj: any :func:`dumpable` object

    :returns: a byte-string representation of the object
    """
    stream = []
    _dump(obj, stream, version)
    return b''.join(stream)


def load(data, version=0):
    """Recreates (loads) an object from its byte-string representation

    :param data: the byte-string representation of an object

    :returns: the dumped object
    """
    stream = BytesIO(data)
    return _load(stream, version)


if is_py3k:
    simple_types = frozenset([
        type(None), int, bool, float, bytes, str, complex,
        type(NotImplemented), type(Ellipsis)
    ])
else:
    simple_types = frozenset([
        type(None), int, long, bool, float, str, unicode, complex,
        type(NotImplemented), type(Ellipsis)
    ])


def dumpable(obj, version=0, log_deep=False, copy_mutable=True):
    """Indicates whether the given object is *dumpable* by brine

    :returns: ``True`` if the object is dumpable (e.g., :func:`dump`
                    would succeed),
              ``False`` otherwise
    """
    if type(obj) in simple_types:
        return True

    if type(obj) in (tuple, frozenset):
        return all(dumpable(item, version, log_deep) for item in obj)

    if type(obj) is slice:
        return \
            dumpable(obj.start, version, log_deep) and \
            dumpable(obj.stop, version, log_deep) and \
            dumpable(obj.step, version, log_deep)

    if type(obj) in _dump_registry[version]:
        if isinstance(obj, tuple) or (type(obj) is set and copy_mutable):
            return all(dumpable(item, version, True) for item in obj)
        elif type(obj) is dict and copy_mutable:
            return all(
                dumpable(k, version, True) and dumpable(v, version, True)
                for k, v in obj.items()
            )

    if __debug__:
        if log_deep:
            logging.debug(
                'dumpable(deep): undumpable object type %s (%s)',
                type(obj), repr(obj)
            )

    return False


if __name__ == "__main__":
    import doctest
    doctest.testmod()
