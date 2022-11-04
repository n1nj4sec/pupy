# u-msgpack-python v2.7.1 - v at sergeev.io
# https://github.com/vsergeev/u-msgpack-python
#
# u-msgpack-python is a lightweight MessagePack serializer and deserializer
# module, compatible with both Python 2 and 3, as well CPython and PyPy
# implementations of Python. u-msgpack-python is fully compliant with the
# latest MessagePack specification.com/msgpack/msgpack/blob/master/spec.md). In
# particular, it supports the new binary, UTF-8 string, and application ext
# types.
#
# MIT License
#
# Copyright (c) 2013-2020 vsergeev / Ivan (Vanya) A. Sergeev
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
"""
u-msgpack-python v2.7.1 - v at sergeev.io
https://github.com/vsergeev/u-msgpack-python

u-msgpack-python is a lightweight MessagePack serializer and deserializer
module, compatible with both Python 2 and 3, as well CPython and PyPy
implementations of Python. u-msgpack-python is fully compliant with the
latest MessagePack specification.com/msgpack/msgpack/blob/master/spec.md). In
particular, it supports the new binary, UTF-8 string, and application ext
types.

License: MIT
"""
import struct
import collections
import datetime
import sys
import io

if sys.version_info[0:2] >= (3, 3):
    from collections.abc import Hashable
else:
    from collections import Hashable

__version__ = "2.7.1"
"Module version string"

version = (2, 7, 1)
"Module version tuple"


##############################################################################
# Ext Class
##############################################################################

# Extension type for application-defined types and data
class Ext(object):
    """
    The Ext class facilitates creating a serializable extension object to store
    an application-defined type and data byte array.
    """

    def __init__(self, type, data):
        """
        Construct a new Ext object.

        Args:
            type: application-defined type integer
            data: application-defined data byte array

        TypeError:
            Type is not an integer.
        ValueError:
            Type is out of range of -128 to 127.
        TypeError::
            Data is not type 'bytes' (Python 3) or not type 'str' (Python 2).

        Example:
        >>> foo = umsgpack.Ext(5, b"\x01\x02\x03")
        >>> umsgpack.packb({u"special stuff": foo, u"awesome": True})
        '\x82\xa7awesome\xc3\xadspecial stuff\xc7\x03\x05\x01\x02\x03'
        >>> bar = umsgpack.unpackb(_)
        >>> print(bar["special stuff"])
        Ext Object (Type: 5, Data: 01 02 03)
        >>>
        """
        # Check type is type int and in range
        if not isinstance(type, int):
            raise TypeError("ext type is not type integer")
        elif not (-2**7 <= type <= 2**7 - 1):
            raise ValueError("ext type value {:d} is out of range (-128 to 127)".format(type))
        # Check data is type bytes or str
        elif sys.version_info[0] == 3 and not isinstance(data, bytes):
            raise TypeError("ext data is not type \'bytes\'")
        elif sys.version_info[0] == 2 and not isinstance(data, str):
            raise TypeError("ext data is not type \'str\'")

        self.type = type
        self.data = data

    def __eq__(self, other):
        """
        Compare this Ext object with another for equality.
        """
        return isinstance(other, self.__class__) \
            and self.type == other.type and self.data == other.data

    def __ne__(self, other):
        """
        Compare this Ext object with another for inequality.
        """
        return not self.__eq__(other)

    def __str__(self):
        """
        String representation of this Ext object.
        """
        s = "Ext Object (Type: {:d}, Data: ".format(self.type)
        s += " ".join(["0x{:02}".format(ord(self.data[i:i + 1]))
                       for i in xrange(min(len(self.data), 8))])
        if len(self.data) > 8:
            s += " ..."
        s += ")"
        return s

    def __hash__(self):
        """
        Provide a hash of this Ext object.
        """
        return hash((self.type, self.data))


class InvalidString(bytes):
    """Subclass of bytes to hold invalid UTF-8 strings."""


##############################################################################
# Ext Serializable Decorator
##############################################################################

_ext_class_to_type = {}
_ext_type_to_class = {}


def ext_serializable(ext_type):
    """
    Return a decorator to register a class for automatic packing and unpacking
    with the specified Ext type code. The application class should implement a
    `packb()` method that returns serialized bytes, and an `unpackb()` class
    method or static method that accepts serialized bytes and returns an
    instance of the application class.

    Args:
        ext_type: application-defined Ext type code

    Raises:
        TypeError:
            Ext type is not an integer.
        ValueError:
            Ext type is out of range of -128 to 127.
        ValueError:
            Ext type or class already registered.
    """
    def wrapper(cls):
        if not isinstance(ext_type, int):
            raise TypeError("Ext type is not type integer")
        elif not (-2**7 <= ext_type <= 2**7 - 1):
            raise ValueError("Ext type value {:d} is out of range of -128 to 127".format(ext_type))
        elif ext_type in _ext_type_to_class:
            raise ValueError("Ext type {:d} already registered with class {:s}".format(ext_type, repr(_ext_type_to_class[ext_type])))
        elif cls in _ext_class_to_type:
            raise ValueError("Class {:s} already registered with Ext type {:d}".format(repr(cls), ext_type))

        _ext_type_to_class[ext_type] = cls
        _ext_class_to_type[cls] = ext_type

        return cls

    return wrapper


##############################################################################
# Exceptions
##############################################################################


# Base Exception classes
class PackException(Exception):
    "Base class for exceptions encountered during packing."


class UnpackException(Exception):
    "Base class for exceptions encountered during unpacking."


# Packing error
class UnsupportedTypeException(PackException):
    "Object type not supported for packing."


# Unpacking error
class InsufficientDataException(UnpackException):
    "Insufficient data to unpack the serialized object."


class InvalidStringException(UnpackException):
    "Invalid UTF-8 string encountered during unpacking."


class UnsupportedTimestampException(UnpackException):
    "Unsupported timestamp format encountered during unpacking."


class ReservedCodeException(UnpackException):
    "Reserved code encountered during unpacking."


class UnhashableKeyException(UnpackException):
    """
    Unhashable key encountered during map unpacking.
    The serialized map cannot be deserialized into a Python dictionary.
    """


class DuplicateKeyException(UnpackException):
    "Duplicate key encountered during map unpacking."


# Backwards compatibility
KeyNotPrimitiveException = UnhashableKeyException
KeyDuplicateException = DuplicateKeyException

#############################################################################
# Exported Functions and Glob
#############################################################################

# Exported functions and variables, set up in __init()
pack = None
packb = None
unpack = None
unpackb = None
dump = None
dumps = None
load = None
loads = None

compatibility = False
"""
Compatibility mode boolean.

When compatibility mode is enabled, u-msgpack-python will serialize both
unicode strings and bytes into the old "raw" msgpack type, and deserialize the
"raw" msgpack type into bytes. This provides backwards compatibility with the
old MessagePack specification.

Example:
>>> umsgpack.compatibility = True
>>>
>>> umsgpack.packb([u"some string", b"some bytes"])
b'\x92\xabsome string\xaasome bytes'
>>> umsgpack.unpackb(_)
[b'some string', b'some bytes']
>>>
"""

##############################################################################
# Packing
##############################################################################

# You may notice struct.pack("B", obj) instead of the simpler chr(obj) in the
# code below. This is to allow for seamless Python 2 and 3 compatibility, as
# chr(obj) has a str return type instead of bytes in Python 3, and
# struct.pack(...) has the right return type in both versions.


def _pack_integer(obj, fp, options):
    if obj < 0:
        if obj >= -32:
            fp.write(struct.pack("b", obj))
        elif obj >= -2**(8 - 1):
            fp.write(b"\xd0" + struct.pack("b", obj))
        elif obj >= -2**(16 - 1):
            fp.write(b"\xd1" + struct.pack(">h", obj))
        elif obj >= -2**(32 - 1):
            fp.write(b"\xd2" + struct.pack(">i", obj))
        elif obj >= -2**(64 - 1):
            fp.write(b"\xd3" + struct.pack(">q", obj))
        else:
            raise UnsupportedTypeException("huge signed int")
    else:
        if obj < 128:
            fp.write(struct.pack("B", obj))
        elif obj < 2**8:
            fp.write(b"\xcc" + struct.pack("B", obj))
        elif obj < 2**16:
            fp.write(b"\xcd" + struct.pack(">H", obj))
        elif obj < 2**32:
            fp.write(b"\xce" + struct.pack(">I", obj))
        elif obj < 2**64:
            fp.write(b"\xcf" + struct.pack(">Q", obj))
        else:
            raise UnsupportedTypeException("huge unsigned int")


def _pack_nil(obj, fp, options):
    fp.write(b"\xc0")


def _pack_boolean(obj, fp, options):
    fp.write(b"\xc3" if obj else b"\xc2")


def _pack_float(obj, fp, options):
    float_precision = options.get('force_float_precision', _float_precision)

    if float_precision == "double":
        fp.write(b"\xcb" + struct.pack(">d", obj))
    elif float_precision == "single":
        fp.write(b"\xca" + struct.pack(">f", obj))
    else:
        raise ValueError("invalid float precision")


def _pack_string(obj, fp, options):
    obj = obj.encode('utf-8')
    obj_len = len(obj)
    if obj_len < 32:
        fp.write(struct.pack("B", 0xa0 | obj_len) + obj)
    elif obj_len < 2**8:
        fp.write(b"\xd9" + struct.pack("B", obj_len) + obj)
    elif obj_len < 2**16:
        fp.write(b"\xda" + struct.pack(">H", obj_len) + obj)
    elif obj_len < 2**32:
        fp.write(b"\xdb" + struct.pack(">I", obj_len) + obj)
    else:
        raise UnsupportedTypeException("huge string")


def _pack_binary(obj, fp, options):
    obj_len = len(obj)
    if obj_len < 2**8:
        fp.write(b"\xc4" + struct.pack("B", obj_len) + obj)
    elif obj_len < 2**16:
        fp.write(b"\xc5" + struct.pack(">H", obj_len) + obj)
    elif obj_len < 2**32:
        fp.write(b"\xc6" + struct.pack(">I", obj_len) + obj)
    else:
        raise UnsupportedTypeException("huge binary string")


def _pack_oldspec_raw(obj, fp, options):
    obj_len = len(obj)
    if obj_len < 32:
        fp.write(struct.pack("B", 0xa0 | obj_len) + obj)
    elif obj_len < 2**16:
        fp.write(b"\xda" + struct.pack(">H", obj_len) + obj)
    elif obj_len < 2**32:
        fp.write(b"\xdb" + struct.pack(">I", obj_len) + obj)
    else:
        raise UnsupportedTypeException("huge raw string")


def _pack_ext(obj, fp, options):
    obj_len = len(obj.data)
    if obj_len == 1:
        fp.write(b"\xd4" + struct.pack("B", obj.type & 0xff) + obj.data)
    elif obj_len == 2:
        fp.write(b"\xd5" + struct.pack("B", obj.type & 0xff) + obj.data)
    elif obj_len == 4:
        fp.write(b"\xd6" + struct.pack("B", obj.type & 0xff) + obj.data)
    elif obj_len == 8:
        fp.write(b"\xd7" + struct.pack("B", obj.type & 0xff) + obj.data)
    elif obj_len == 16:
        fp.write(b"\xd8" + struct.pack("B", obj.type & 0xff) + obj.data)
    elif obj_len < 2**8:
        fp.write(b"\xc7" + struct.pack("BB", obj_len, obj.type & 0xff) + obj.data)
    elif obj_len < 2**16:
        fp.write(b"\xc8" + struct.pack(">HB", obj_len, obj.type & 0xff) + obj.data)
    elif obj_len < 2**32:
        fp.write(b"\xc9" + struct.pack(">IB", obj_len, obj.type & 0xff) + obj.data)
    else:
        raise UnsupportedTypeException("huge ext data")


def _pack_ext_timestamp(obj, fp, options):
    if not obj.tzinfo:
        # Object is naive datetime, convert to aware date time,
        # assuming UTC timezone
        delta = obj.replace(tzinfo=_utc_tzinfo) - _epoch
    else:
        # Object is aware datetime
        delta = obj - _epoch

    seconds = delta.seconds + delta.days * 86400
    microseconds = delta.microseconds

    if microseconds == 0 and 0 <= seconds <= 2**32 - 1:
        # 32-bit timestamp
        fp.write(b"\xd6\xff" + struct.pack(">I", seconds))
    elif 0 <= seconds <= 2**34 - 1:
        # 64-bit timestamp
        value = ((microseconds * 1000) << 34) | seconds
        fp.write(b"\xd7\xff" + struct.pack(">Q", value))
    elif -2**63 <= abs(seconds) <= 2**63 - 1:
        # 96-bit timestamp
        fp.write(b"\xc7\x0c\xff" + struct.pack(">Iq", microseconds * 1000, seconds))
    else:
        raise UnsupportedTypeException("huge timestamp")


def _pack_array(obj, fp, options):
    obj_len = len(obj)
    if obj_len < 16:
        fp.write(struct.pack("B", 0x90 | obj_len))
    elif obj_len < 2**16:
        fp.write(b"\xdc" + struct.pack(">H", obj_len))
    elif obj_len < 2**32:
        fp.write(b"\xdd" + struct.pack(">I", obj_len))
    else:
        raise UnsupportedTypeException("huge array")

    for e in obj:
        pack(e, fp, **options)


def _pack_map(obj, fp, options):
    obj_len = len(obj)
    if obj_len < 16:
        fp.write(struct.pack("B", 0x80 | obj_len))
    elif obj_len < 2**16:
        fp.write(b"\xde" + struct.pack(">H", obj_len))
    elif obj_len < 2**32:
        fp.write(b"\xdf" + struct.pack(">I", obj_len))
    else:
        raise UnsupportedTypeException("huge array")

    for k, v in obj.items():
        pack(k, fp, **options)
        pack(v, fp, **options)

########################################


# Pack for Python 2, with 'unicode' type, 'str' type, and 'long' type
def _pack2(obj, fp, **options):
    """
    Serialize a Python object into MessagePack bytes.

    Args:
        obj: a Python object
        fp: a .write()-supporting file-like object

    Kwargs:
        ext_handlers (dict): dictionary of Ext handlers, mapping a custom type
                             to a callable that packs an instance of the type
                             into an Ext object
        force_float_precision (str): "single" to force packing floats as
                                     IEEE-754 single-precision floats,
                                     "double" to force packing floats as
                                     IEEE-754 double-precision floats.

    Returns:
        None.

    Raises:
        UnsupportedType(PackException):
            Object type not supported for packing.

    Example:
    >>> f = open('test.bin', 'wb')
    >>> umsgpack.pack({u"compact": True, u"schema": 0}, f)
    >>>
    """
    global compatibility

    ext_handlers = options.get("ext_handlers")

    if obj is None:
        _pack_nil(obj, fp, options)
    elif ext_handlers and obj.__class__ in ext_handlers:
        _pack_ext(ext_handlers[obj.__class__](obj), fp, options)
    elif obj.__class__ in _ext_class_to_type:
        try:
            _pack_ext(Ext(_ext_class_to_type[obj.__class__], obj.packb()), fp, options)
        except AttributeError:
            raise NotImplementedError("Ext serializable class {:s} is missing implementation of packb()".format(repr(obj.__class__)))
    elif isinstance(obj, bool):
        _pack_boolean(obj, fp, options)
    elif isinstance(obj, (int, long)):
        _pack_integer(obj, fp, options)
    elif isinstance(obj, float):
        _pack_float(obj, fp, options)
    elif compatibility and isinstance(obj, unicode):
        _pack_oldspec_raw(bytes(obj), fp, options)
    elif compatibility and isinstance(obj, bytes):
        _pack_oldspec_raw(obj, fp, options)
    elif isinstance(obj, unicode):
        _pack_string(obj, fp, options)
    elif isinstance(obj, str):
        _pack_binary(obj, fp, options)
    elif isinstance(obj, (list, tuple)):
        _pack_array(obj, fp, options)
    elif isinstance(obj, dict):
        _pack_map(obj, fp, options)
    elif isinstance(obj, datetime.datetime):
        _pack_ext_timestamp(obj, fp, options)
    elif isinstance(obj, Ext):
        _pack_ext(obj, fp, options)
    elif ext_handlers:
        # Linear search for superclass
        t = next((t for t in ext_handlers.keys() if isinstance(obj, t)), None)
        if t:
            _pack_ext(ext_handlers[t](obj), fp, options)
        else:
            raise UnsupportedTypeException(
                "unsupported type: {:s}".format(str(type(obj))))
    elif _ext_class_to_type:
        # Linear search for superclass
        t = next((t for t in _ext_class_to_type if isinstance(obj, t)), None)
        if t:
            try:
                _pack_ext(Ext(_ext_class_to_type[t], obj.packb()), fp, options)
            except AttributeError:
                raise NotImplementedError("Ext serializable class {:s} is missing implementation of packb()".format(repr(t)))
        else:
            raise UnsupportedTypeException("unsupported type: {:s}".format(str(type(obj))))
    else:
        raise UnsupportedTypeException("unsupported type: {:s}".format(str(type(obj))))


# Pack for Python 3, with unicode 'str' type, 'bytes' type, and no 'long' type
def _pack3(obj, fp, **options):
    """
    Serialize a Python object into MessagePack bytes.

    Args:
        obj: a Python object
        fp: a .write()-supporting file-like object

    Kwargs:
        ext_handlers (dict): dictionary of Ext handlers, mapping a custom type
                             to a callable that packs an instance of the type
                             into an Ext object
        force_float_precision (str): "single" to force packing floats as
                                     IEEE-754 single-precision floats,
                                     "double" to force packing floats as
                                     IEEE-754 double-precision floats.

    Returns:
        None.

    Raises:
        UnsupportedType(PackException):
            Object type not supported for packing.

    Example:
    >>> f = open('test.bin', 'wb')
    >>> umsgpack.pack({u"compact": True, u"schema": 0}, f)
    >>>
    """
    global compatibility

    ext_handlers = options.get("ext_handlers")

    if obj is None:
        _pack_nil(obj, fp, options)
    elif ext_handlers and obj.__class__ in ext_handlers:
        _pack_ext(ext_handlers[obj.__class__](obj), fp, options)
    elif obj.__class__ in _ext_class_to_type:
        try:
            _pack_ext(Ext(_ext_class_to_type[obj.__class__], obj.packb()), fp, options)
        except AttributeError:
            raise NotImplementedError("Ext serializable class {:s} is missing implementation of packb()".format(repr(obj.__class__)))
    elif isinstance(obj, bool):
        _pack_boolean(obj, fp, options)
    elif isinstance(obj, int):
        _pack_integer(obj, fp, options)
    elif isinstance(obj, float):
        _pack_float(obj, fp, options)
    elif compatibility and isinstance(obj, str):
        _pack_oldspec_raw(obj.encode('utf-8'), fp, options)
    elif compatibility and isinstance(obj, bytes):
        _pack_oldspec_raw(obj, fp, options)
    elif isinstance(obj, str):
        _pack_string(obj, fp, options)
    elif isinstance(obj, bytes):
        _pack_binary(obj, fp, options)
    elif isinstance(obj, (list, tuple)):
        _pack_array(obj, fp, options)
    elif isinstance(obj, dict):
        _pack_map(obj, fp, options)
    elif isinstance(obj, datetime.datetime):
        _pack_ext_timestamp(obj, fp, options)
    elif isinstance(obj, Ext):
        _pack_ext(obj, fp, options)
    elif ext_handlers:
        # Linear search for superclass
        t = next((t for t in ext_handlers.keys() if isinstance(obj, t)), None)
        if t:
            _pack_ext(ext_handlers[t](obj), fp, options)
        else:
            raise UnsupportedTypeException(
                "unsupported type: {:s}".format(str(type(obj))))
    elif _ext_class_to_type:
        # Linear search for superclass
        t = next((t for t in _ext_class_to_type if isinstance(obj, t)), None)
        if t:
            try:
                _pack_ext(Ext(_ext_class_to_type[t], obj.packb()), fp, options)
            except AttributeError:
                raise NotImplementedError("Ext serializable class {:s} is missing implementation of packb()".format(repr(t)))
        else:
            raise UnsupportedTypeException("unsupported type: {:s}".format(str(type(obj))))
    else:
        raise UnsupportedTypeException(
            "unsupported type: {:s}".format(str(type(obj))))


def _packb2(obj, **options):
    """
    Serialize a Python object into MessagePack bytes.

    Args:
        obj: a Python object

    Kwargs:
        ext_handlers (dict): dictionary of Ext handlers, mapping a custom type
                             to a callable that packs an instance of the type
                             into an Ext object
        force_float_precision (str): "single" to force packing floats as
                                     IEEE-754 single-precision floats,
                                     "double" to force packing floats as
                                     IEEE-754 double-precision floats.

    Returns:
        A 'str' containing serialized MessagePack bytes.

    Raises:
        UnsupportedType(PackException):
            Object type not supported for packing.

    Example:
    >>> umsgpack.packb({u"compact": True, u"schema": 0})
    '\x82\xa7compact\xc3\xa6schema\x00'
    >>>
    """
    fp = io.BytesIO()
    _pack2(obj, fp, **options)
    return fp.getvalue()


def _packb3(obj, **options):
    """
    Serialize a Python object into MessagePack bytes.

    Args:
        obj: a Python object

    Kwargs:
        ext_handlers (dict): dictionary of Ext handlers, mapping a custom type
                             to a callable that packs an instance of the type
                             into an Ext object
        force_float_precision (str): "single" to force packing floats as
                                     IEEE-754 single-precision floats,
                                     "double" to force packing floats as
                                     IEEE-754 double-precision floats.

    Returns:
        A 'bytes' containing serialized MessagePack bytes.

    Raises:
        UnsupportedType(PackException):
            Object type not supported for packing.

    Example:
    >>> umsgpack.packb({u"compact": True, u"schema": 0})
    b'\x82\xa7compact\xc3\xa6schema\x00'
    >>>
    """
    fp = io.BytesIO()
    _pack3(obj, fp, **options)
    return fp.getvalue()

#############################################################################
# Unpacking
#############################################################################


def _read_except(fp, n):
    if n == 0:
        return b""

    data = fp.read(n)
    if len(data) == 0:
        raise InsufficientDataException()

    while len(data) < n:
        chunk = fp.read(n - len(data))
        if len(chunk) == 0:
            raise InsufficientDataException()

        data += chunk

    return data


def _unpack_integer(code, fp, options):
    if (ord(code) & 0xe0) == 0xe0:
        return struct.unpack("b", code)[0]
    elif code == b'\xd0':
        return struct.unpack("b", _read_except(fp, 1))[0]
    elif code == b'\xd1':
        return struct.unpack(">h", _read_except(fp, 2))[0]
    elif code == b'\xd2':
        return struct.unpack(">i", _read_except(fp, 4))[0]
    elif code == b'\xd3':
        return struct.unpack(">q", _read_except(fp, 8))[0]
    elif (ord(code) & 0x80) == 0x00:
        return struct.unpack("B", code)[0]
    elif code == b'\xcc':
        return struct.unpack("B", _read_except(fp, 1))[0]
    elif code == b'\xcd':
        return struct.unpack(">H", _read_except(fp, 2))[0]
    elif code == b'\xce':
        return struct.unpack(">I", _read_except(fp, 4))[0]
    elif code == b'\xcf':
        return struct.unpack(">Q", _read_except(fp, 8))[0]
    raise Exception("logic error, not int: 0x{:02x}".format(ord(code)))


def _unpack_reserved(code, fp, options):
    if code == b'\xc1':
        raise ReservedCodeException(
            "encountered reserved code: 0x{:02x}".format(ord(code)))
    raise Exception(
        "logic error, not reserved code: 0x{:02x}".format(ord(code)))


def _unpack_nil(code, fp, options):
    if code == b'\xc0':
        return None
    raise Exception("logic error, not nil: 0x{:02x}".format(ord(code)))


def _unpack_boolean(code, fp, options):
    if code == b'\xc2':
        return False
    elif code == b'\xc3':
        return True
    raise Exception("logic error, not boolean: 0x{:02x}".format(ord(code)))


def _unpack_float(code, fp, options):
    if code == b'\xca':
        return struct.unpack(">f", _read_except(fp, 4))[0]
    elif code == b'\xcb':
        return struct.unpack(">d", _read_except(fp, 8))[0]
    raise Exception("logic error, not float: 0x{:02x}".format(ord(code)))


def _unpack_string(code, fp, options):
    if (ord(code) & 0xe0) == 0xa0:
        length = ord(code) & ~0xe0
    elif code == b'\xd9':
        length = struct.unpack("B", _read_except(fp, 1))[0]
    elif code == b'\xda':
        length = struct.unpack(">H", _read_except(fp, 2))[0]
    elif code == b'\xdb':
        length = struct.unpack(">I", _read_except(fp, 4))[0]
    else:
        raise Exception("logic error, not string: 0x{:02x}".format(ord(code)))

    # Always return raw bytes in compatibility mode
    global compatibility
    if compatibility:
        return _read_except(fp, length)

    data = _read_except(fp, length)
    try:
        return bytes.decode(data, 'utf-8')
    except UnicodeDecodeError:
        if options.get("allow_invalid_utf8"):
            return InvalidString(data)
        raise InvalidStringException("unpacked string is invalid utf-8")


def _unpack_binary(code, fp, options):
    if code == b'\xc4':
        length = struct.unpack("B", _read_except(fp, 1))[0]
    elif code == b'\xc5':
        length = struct.unpack(">H", _read_except(fp, 2))[0]
    elif code == b'\xc6':
        length = struct.unpack(">I", _read_except(fp, 4))[0]
    else:
        raise Exception("logic error, not binary: 0x{:02x}".format(ord(code)))

    return _read_except(fp, length)


def _unpack_ext(code, fp, options):
    if code == b'\xd4':
        length = 1
    elif code == b'\xd5':
        length = 2
    elif code == b'\xd6':
        length = 4
    elif code == b'\xd7':
        length = 8
    elif code == b'\xd8':
        length = 16
    elif code == b'\xc7':
        length = struct.unpack("B", _read_except(fp, 1))[0]
    elif code == b'\xc8':
        length = struct.unpack(">H", _read_except(fp, 2))[0]
    elif code == b'\xc9':
        length = struct.unpack(">I", _read_except(fp, 4))[0]
    else:
        raise Exception("logic error, not ext: 0x{:02x}".format(ord(code)))

    ext_type = struct.unpack("b", _read_except(fp, 1))[0]
    ext_data = _read_except(fp, length)

    # Unpack with ext handler, if we have one
    ext_handlers = options.get("ext_handlers")
    if ext_handlers and ext_type in ext_handlers:
        return ext_handlers[ext_type](Ext(ext_type, ext_data))

    # Unpack with ext classes, if type is registered
    if ext_type in _ext_type_to_class:
        try:
            return _ext_type_to_class[ext_type].unpackb(ext_data)
        except AttributeError:
            raise NotImplementedError("Ext serializable class {:s} is missing implementation of unpackb()".format(repr(_ext_type_to_class[ext_type])))

    # Timestamp extension
    if ext_type == -1:
        return _unpack_ext_timestamp(ext_data, options)

    return Ext(ext_type, ext_data)


def _unpack_ext_timestamp(ext_data, options):
    obj_len = len(ext_data)
    if obj_len == 4:
        # 32-bit timestamp
        seconds = struct.unpack(">I", ext_data)[0]
        microseconds = 0
    elif obj_len == 8:
        # 64-bit timestamp
        value = struct.unpack(">Q", ext_data)[0]
        seconds = value & 0x3ffffffff
        microseconds = (value >> 34) // 1000
    elif obj_len == 12:
        # 96-bit timestamp
        seconds = struct.unpack(">q", ext_data[4:12])[0]
        microseconds = struct.unpack(">I", ext_data[0:4])[0] // 1000
    else:
        raise UnsupportedTimestampException(
            "unsupported timestamp with data length {:d}".format(len(ext_data)))

    return _epoch + datetime.timedelta(seconds=seconds,
                                       microseconds=microseconds)


def _unpack_array(code, fp, options):
    if (ord(code) & 0xf0) == 0x90:
        length = (ord(code) & ~0xf0)
    elif code == b'\xdc':
        length = struct.unpack(">H", _read_except(fp, 2))[0]
    elif code == b'\xdd':
        length = struct.unpack(">I", _read_except(fp, 4))[0]
    else:
        raise Exception("logic error, not array: 0x{:02x}".format(ord(code)))

    if options.get('use_tuple'):
        return tuple((_unpack(fp, options) for i in xrange(length)))

    return [_unpack(fp, options) for i in xrange(length)]


def _deep_list_to_tuple(obj):
    if isinstance(obj, list):
        return tuple([_deep_list_to_tuple(e) for e in obj])
    return obj


def _unpack_map(code, fp, options):
    if (ord(code) & 0xf0) == 0x80:
        length = (ord(code) & ~0xf0)
    elif code == b'\xde':
        length = struct.unpack(">H", _read_except(fp, 2))[0]
    elif code == b'\xdf':
        length = struct.unpack(">I", _read_except(fp, 4))[0]
    else:
        raise Exception("logic error, not map: 0x{:02x}".format(ord(code)))

    d = {} if not options.get('use_ordered_dict') else collections.OrderedDict()
    for _ in xrange(length):
        # Unpack key
        k = _unpack(fp, options)

        if isinstance(k, list):
            # Attempt to convert list into a hashable tuple
            k = _deep_list_to_tuple(k)
        elif not isinstance(k, Hashable):
            raise UnhashableKeyException(
                "encountered unhashable key: \"{:s}\" ({:s})".format(str(k), str(type(k))))
        elif k in d:
            raise DuplicateKeyException(
                "encountered duplicate key: \"{:s}\" ({:s})".format(str(k), str(type(k))))

        # Unpack value
        v = _unpack(fp, options)

        try:
            d[k] = v
        except TypeError:
            raise UnhashableKeyException(
                "encountered unhashable key: \"{:s}\"".format(str(k)))
    return d


def _unpack(fp, options):
    code = _read_except(fp, 1)
    return _unpack_dispatch_table[code](code, fp, options)

########################################


def _unpack2(fp, **options):
    """
    Deserialize MessagePack bytes into a Python object.

    Args:
        fp: a .read()-supporting file-like object

    Kwargs:
        ext_handlers (dict): dictionary of Ext handlers, mapping integer Ext
                             type to a callable that unpacks an instance of
                             Ext into an object
        use_ordered_dict (bool): unpack maps into OrderedDict, instead of
                                 unordered dict (default False)
        use_tuple (bool): unpacks arrays into tuples, instead of lists (default
                          False)
        allow_invalid_utf8 (bool): unpack invalid strings into instances of
                                   InvalidString, for access to the bytes
                                   (default False)

    Returns:
        A Python object.

    Raises:
        InsufficientDataException(UnpackException):
            Insufficient data to unpack the serialized object.
        InvalidStringException(UnpackException):
            Invalid UTF-8 string encountered during unpacking.
        UnsupportedTimestampException(UnpackException):
            Unsupported timestamp format encountered during unpacking.
        ReservedCodeException(UnpackException):
            Reserved code encountered during unpacking.
        UnhashableKeyException(UnpackException):
            Unhashable key encountered during map unpacking.
            The serialized map cannot be deserialized into a Python dictionary.
        DuplicateKeyException(UnpackException):
            Duplicate key encountered during map unpacking.

    Example:
    >>> f = open('test.bin', 'rb')
    >>> umsgpack.unpackb(f)
    {u'compact': True, u'schema': 0}
    >>>
    """
    return _unpack(fp, options)


def _unpack3(fp, **options):
    """
    Deserialize MessagePack bytes into a Python object.

    Args:
        fp: a .read()-supporting file-like object

    Kwargs:
        ext_handlers (dict): dictionary of Ext handlers, mapping integer Ext
                             type to a callable that unpacks an instance of
                             Ext into an object
        use_ordered_dict (bool): unpack maps into OrderedDict, instead of
                                 unordered dict (default False)
        use_tuple (bool): unpacks arrays into tuples, instead of lists (default
                          False)
        allow_invalid_utf8 (bool): unpack invalid strings into instances of
                                   InvalidString, for access to the bytes
                                   (default False)

    Returns:
        A Python object.

    Raises:
        InsufficientDataException(UnpackException):
            Insufficient data to unpack the serialized object.
        InvalidStringException(UnpackException):
            Invalid UTF-8 string encountered during unpacking.
        UnsupportedTimestampException(UnpackException):
            Unsupported timestamp format encountered during unpacking.
        ReservedCodeException(UnpackException):
            Reserved code encountered during unpacking.
        UnhashableKeyException(UnpackException):
            Unhashable key encountered during map unpacking.
            The serialized map cannot be deserialized into a Python dictionary.
        DuplicateKeyException(UnpackException):
            Duplicate key encountered during map unpacking.

    Example:
    >>> f = open('test.bin', 'rb')
    >>> umsgpack.unpackb(f)
    {'compact': True, 'schema': 0}
    >>>
    """
    return _unpack(fp, options)


# For Python 2, expects a str object
def _unpackb2(s, **options):
    """
    Deserialize MessagePack bytes into a Python object.

    Args:
        s: a 'str' or 'bytearray' containing serialized MessagePack bytes

    Kwargs:
        ext_handlers (dict): dictionary of Ext handlers, mapping integer Ext
                             type to a callable that unpacks an instance of
                             Ext into an object
        use_ordered_dict (bool): unpack maps into OrderedDict, instead of
                                 unordered dict (default False)
        use_tuple (bool): unpacks arrays into tuples, instead of lists (default
                          False)
        allow_invalid_utf8 (bool): unpack invalid strings into instances of
                                   InvalidString, for access to the bytes
                                   (default False)

    Returns:
        A Python object.

    Raises:
        TypeError:
            Packed data type is neither 'str' nor 'bytearray'.
        InsufficientDataException(UnpackException):
            Insufficient data to unpack the serialized object.
        InvalidStringException(UnpackException):
            Invalid UTF-8 string encountered during unpacking.
        UnsupportedTimestampException(UnpackException):
            Unsupported timestamp format encountered during unpacking.
        ReservedCodeException(UnpackException):
            Reserved code encountered during unpacking.
        UnhashableKeyException(UnpackException):
            Unhashable key encountered during map unpacking.
            The serialized map cannot be deserialized into a Python dictionary.
        DuplicateKeyException(UnpackException):
            Duplicate key encountered during map unpacking.

    Example:
    >>> umsgpack.unpackb(b'\x82\xa7compact\xc3\xa6schema\x00')
    {u'compact': True, u'schema': 0}
    >>>
    """
    if not isinstance(s, (str, bytearray)):
        raise TypeError("packed data must be type 'str' or 'bytearray'")
    return _unpack(io.BytesIO(s), options)


# For Python 3, expects a bytes object
def _unpackb3(s, **options):
    """
    Deserialize MessagePack bytes into a Python object.

    Args:
        s: a 'bytes' or 'bytearray' containing serialized MessagePack bytes

    Kwargs:
        ext_handlers (dict): dictionary of Ext handlers, mapping integer Ext
                             type to a callable that unpacks an instance of
                             Ext into an object
        use_ordered_dict (bool): unpack maps into OrderedDict, instead of
                                 unordered dict (default False)
        use_tuple (bool): unpacks arrays into tuples, instead of lists (default
                          False)
        allow_invalid_utf8 (bool): unpack invalid strings into instances of
                                   InvalidString, for access to the bytes
                                   (default False)

    Returns:
        A Python object.

    Raises:
        TypeError:
            Packed data type is neither 'bytes' nor 'bytearray'.
        InsufficientDataException(UnpackException):
            Insufficient data to unpack the serialized object.
        InvalidStringException(UnpackException):
            Invalid UTF-8 string encountered during unpacking.
        UnsupportedTimestampException(UnpackException):
            Unsupported timestamp format encountered during unpacking.
        ReservedCodeException(UnpackException):
            Reserved code encountered during unpacking.
        UnhashableKeyException(UnpackException):
            Unhashable key encountered during map unpacking.
            The serialized map cannot be deserialized into a Python dictionary.
        DuplicateKeyException(UnpackException):
            Duplicate key encountered during map unpacking.

    Example:
    >>> umsgpack.unpackb(b'\x82\xa7compact\xc3\xa6schema\x00')
    {'compact': True, 'schema': 0}
    >>>
    """
    if not isinstance(s, (bytes, bytearray)):
        raise TypeError("packed data must be type 'bytes' or 'bytearray'")
    return _unpack(io.BytesIO(s), options)

#############################################################################
# Module Initialization
#############################################################################


def __init():
    global pack
    global packb
    global unpack
    global unpackb
    global dump
    global dumps
    global load
    global loads
    global compatibility
    global _epoch
    global _utc_tzinfo
    global _float_precision
    global _unpack_dispatch_table
    global xrange

    # Compatibility mode for handling strings/bytes with the old specification
    compatibility = False

    if sys.version_info[0] == 3:
        _utc_tzinfo = datetime.timezone.utc
    else:
        class UTC(datetime.tzinfo):
            ZERO = datetime.timedelta(0)

            def utcoffset(self, dt):
                return UTC.ZERO

            def tzname(self, dt):
                return "UTC"

            def dst(self, dt):
                return UTC.ZERO

        _utc_tzinfo = UTC()

    # Calculate an aware epoch datetime
    _epoch = datetime.datetime(1970, 1, 1, tzinfo=_utc_tzinfo)

    # Auto-detect system float precision
    if sys.float_info.mant_dig == 53:
        _float_precision = "double"
    else:
        _float_precision = "single"

    # Map packb and unpackb to the appropriate version
    if sys.version_info[0] == 3:
        pack = _pack3
        packb = _packb3
        dump = _pack3
        dumps = _packb3
        unpack = _unpack3
        unpackb = _unpackb3
        load = _unpack3
        loads = _unpackb3
        xrange = range
    else:
        pack = _pack2
        packb = _packb2
        dump = _pack2
        dumps = _packb2
        unpack = _unpack2
        unpackb = _unpackb2
        load = _unpack2
        loads = _unpackb2

    # Build a dispatch table for fast lookup of unpacking function

    _unpack_dispatch_table = {}
    # Fix uint
    for code in range(0, 0x7f + 1):
        _unpack_dispatch_table[struct.pack("B", code)] = _unpack_integer
    # Fix map
    for code in range(0x80, 0x8f + 1):
        _unpack_dispatch_table[struct.pack("B", code)] = _unpack_map
    # Fix array
    for code in range(0x90, 0x9f + 1):
        _unpack_dispatch_table[struct.pack("B", code)] = _unpack_array
    # Fix str
    for code in range(0xa0, 0xbf + 1):
        _unpack_dispatch_table[struct.pack("B", code)] = _unpack_string
    # Nil
    _unpack_dispatch_table[b'\xc0'] = _unpack_nil
    # Reserved
    _unpack_dispatch_table[b'\xc1'] = _unpack_reserved
    # Boolean
    _unpack_dispatch_table[b'\xc2'] = _unpack_boolean
    _unpack_dispatch_table[b'\xc3'] = _unpack_boolean
    # Bin
    for code in range(0xc4, 0xc6 + 1):
        _unpack_dispatch_table[struct.pack("B", code)] = _unpack_binary
    # Ext
    for code in range(0xc7, 0xc9 + 1):
        _unpack_dispatch_table[struct.pack("B", code)] = _unpack_ext
    # Float
    _unpack_dispatch_table[b'\xca'] = _unpack_float
    _unpack_dispatch_table[b'\xcb'] = _unpack_float
    # Uint
    for code in range(0xcc, 0xcf + 1):
        _unpack_dispatch_table[struct.pack("B", code)] = _unpack_integer
    # Int
    for code in range(0xd0, 0xd3 + 1):
        _unpack_dispatch_table[struct.pack("B", code)] = _unpack_integer
    # Fixext
    for code in range(0xd4, 0xd8 + 1):
        _unpack_dispatch_table[struct.pack("B", code)] = _unpack_ext
    # String
    for code in range(0xd9, 0xdb + 1):
        _unpack_dispatch_table[struct.pack("B", code)] = _unpack_string
    # Array
    _unpack_dispatch_table[b'\xdc'] = _unpack_array
    _unpack_dispatch_table[b'\xdd'] = _unpack_array
    # Map
    _unpack_dispatch_table[b'\xde'] = _unpack_map
    _unpack_dispatch_table[b'\xdf'] = _unpack_map
    # Negative fixint
    for code in range(0xe0, 0xff + 1):
        _unpack_dispatch_table[struct.pack("B", code)] = _unpack_integer


__init()
