# u-msgpack-python v2.4.1 - v at sergeev.io
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
# Copyright (c) 2013-2016 vsergeev / Ivan (Vanya) A. Sergeev
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
u-msgpack-python v2.4.1 - v at sergeev.io
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
import sys
import io

__version__ = "2.4.1+"
"Module version string"

version = (2, 4, 1)
"Module version tuple"


##############################################################################
# Ext Class
##############################################################################

# Extension type for application-defined types and data
class Ext:
    """
    The Ext class facilitates creating a serializable extension object to store
    an application-defined type and data byte array.
    """

    def __init__(self, type, data):
        """
        Construct a new Ext object.

        Args:
            type: application-defined type integer from 0 to 127
            data: application-defined data byte array

        Raises:
            TypeError:
                Specified ext type is outside of 0 to 127 range.

        Example:
        >>> foo = umsgpack.Ext(0x05, b"\x01\x02\x03")
        >>> umsgpack.packb({u"special stuff": foo, u"awesome": True})
        '\x82\xa7awesome\xc3\xadspecial stuff\xc7\x03\x05\x01\x02\x03'
        >>> bar = umsgpack.unpackb(_)
        >>> print(bar["special stuff"])
        Ext Object (Type: 0x05, Data: 01 02 03)
        >>>
        """
        # Application ext type should be 0 <= type <= 127
        if not isinstance(type, int) or not (type >= 0 and type <= 127):
            raise TypeError("ext type out of range")
        # Check data is type bytes
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
        return (isinstance(other, self.__class__) and
                self.type == other.type and
                self.data == other.data)

    def __ne__(self, other):
        """
        Compare this Ext object with another for inequality.
        """
        return not self.__eq__(other)

    def __str__(self):
        """
        String representation of this Ext object.
        """
        s = "Ext Object (Type: 0x%02x, Data: " % self.type
        s += " ".join(["0x%02x" % ord(self.data[i:i + 1])
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
    pass

##############################################################################
# Exceptions
##############################################################################


# Base Exception classes
class PackException(Exception):
    "Base class for exceptions encountered during packing."
    pass


class UnpackException(Exception):
    "Base class for exceptions encountered during unpacking."
    pass


# Packing error
class UnsupportedTypeException(PackException):
    "Object type not supported for packing."
    pass


# Unpacking error
class InsufficientDataException(UnpackException):
    "Insufficient data to unpack the serialized object."
    pass


class InvalidStringException(UnpackException):
    "Invalid UTF-8 string encountered during unpacking."
    pass


class ReservedCodeException(UnpackException):
    "Reserved code encountered during unpacking."
    pass


class UnhashableKeyException(UnpackException):
    """
    Unhashable key encountered during map unpacking.
    The serialized map cannot be deserialized into a Python dictionary.
    """
    pass


class DuplicateKeyException(UnpackException):
    "Duplicate key encountered during map unpacking."
    pass


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
        if obj <= 127:
            fp.write(struct.pack("B", obj))
        elif obj <= 2**8 - 1:
            fp.write(b"\xcc" + struct.pack("B", obj))
        elif obj <= 2**16 - 1:
            fp.write(b"\xcd" + struct.pack(">H", obj))
        elif obj <= 2**32 - 1:
            fp.write(b"\xce" + struct.pack(">I", obj))
        elif obj <= 2**64 - 1:
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
    if len(obj) <= 31:
        fp.write(struct.pack("B", 0xa0 | len(obj)) + obj)
    elif len(obj) <= 2**8 - 1:
        fp.write(b"\xd9" + struct.pack("B", len(obj)))
        fp.write(obj)
    elif len(obj) <= 2**16 - 1:
        fp.write(b"\xda" + struct.pack(">H", len(obj)))
        fp.write(obj)
    elif len(obj) <= 2**32 - 1:
        fp.write(b"\xdb" + struct.pack(">I", len(obj)))
        fp.write(obj)
    else:
        raise UnsupportedTypeException("huge string")


def _pack_binary(obj, fp, options):
    if len(obj) <= 2**8 - 1:
        fp.write(b"\xc4" + struct.pack("B", len(obj)) + obj)
    elif len(obj) <= 2**16 - 1:
        fp.write(b"\xc5" + struct.pack(">H", len(obj)))
        fp.write(obj)
    elif len(obj) <= 2**32 - 1:
        fp.write(b"\xc6" + struct.pack(">I", len(obj)))
        fp.write(obj)
    else:
        raise UnsupportedTypeException("huge binary string")


def _pack_oldspec_raw(obj, fp, options):
    if len(obj) <= 31:
        fp.write(struct.pack("B", 0xa0 | len(obj)) + obj)
    elif len(obj) <= 2**16 - 1:
        fp.write(b"\xda" + struct.pack(">H", len(obj)) + obj)
    elif len(obj) <= 2**32 - 1:
        fp.write(b"\xdb" + struct.pack(">I", len(obj)) + obj)
    else:
        raise UnsupportedTypeException("huge raw string")


def _pack_ext(obj, fp, options):
    if len(obj.data) == 1:
        fp.write(b"\xd4" + struct.pack("B", obj.type & 0xff) + obj.data)
    elif len(obj.data) == 2:
        fp.write(b"\xd5" + struct.pack("B", obj.type & 0xff) + obj.data)
    elif len(obj.data) == 4:
        fp.write(b"\xd6" + struct.pack("B", obj.type & 0xff) + obj.data)
    elif len(obj.data) == 8:
        fp.write(b"\xd7" + struct.pack("B", obj.type & 0xff) + obj.data)
    elif len(obj.data) == 16:
        fp.write(b"\xd8" + struct.pack("B", obj.type & 0xff) + obj.data)
    elif len(obj.data) <= 2**8 - 1:
        fp.write(b"\xc7" +
                 struct.pack("BB", len(obj.data), obj.type & 0xff) + obj.data)
    elif len(obj.data) <= 2**16 - 1:
        fp.write(b"\xc8" +
                 struct.pack(">HB", len(obj.data), obj.type & 0xff))
        fp.write(obj.data)
    elif len(obj.data) <= 2**32 - 1:
        fp.write(b"\xc9" +
                 struct.pack(">IB", len(obj.data), obj.type & 0xff))
        fp.write(obj.data)
    else:
        raise UnsupportedTypeException("huge ext data")


def _pack_array(obj, fp, options):
    if len(obj) <= 15:
        fp.write(struct.pack("B", 0x90 | len(obj)))
    elif len(obj) <= 2**16 - 1:
        fp.write(b"\xdc" + struct.pack(">H", len(obj)))
    elif len(obj) <= 2**32 - 1:
        fp.write(b"\xdd" + struct.pack(">I", len(obj)))
    else:
        raise UnsupportedTypeException("huge array")

    for e in obj:
        pack(e, fp, **options)


def _pack_map(obj, fp, options):
    if len(obj) <= 15:
        fp.write(struct.pack("B", 0x80 | len(obj)))
    elif len(obj) <= 2**16 - 1:
        fp.write(b"\xde" + struct.pack(">H", len(obj)))
    elif len(obj) <= 2**32 - 1:
        fp.write(b"\xdf" + struct.pack(">I", len(obj)))
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
    elif isinstance(obj, bool):
        _pack_boolean(obj, fp, options)
    elif isinstance(obj, int) or isinstance(obj, long):
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
    elif isinstance(obj, list) or isinstance(obj, tuple):
        _pack_array(obj, fp, options)
    elif isinstance(obj, dict):
        _pack_map(obj, fp, options)
    elif isinstance(obj, Ext):
        _pack_ext(obj, fp, options)
    elif ext_handlers:
        # Linear search for superclass
        t = next((t for t in ext_handlers.keys() if isinstance(obj, t)), None)
        if t:
            _pack_ext(ext_handlers[t](obj), fp, options)
        else:
            raise UnsupportedTypeException(
                "unsupported type: %s" % str(type(obj)))
    else:
        raise UnsupportedTypeException("unsupported type: %s" % str(type(obj)))


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
    elif isinstance(obj, list) or isinstance(obj, tuple):
        _pack_array(obj, fp, options)
    elif isinstance(obj, dict):
        _pack_map(obj, fp, options)
    elif isinstance(obj, Ext):
        _pack_ext(obj, fp, options)
    elif ext_handlers:
        # Linear search for superclass
        t = next((t for t in ext_handlers.keys() if isinstance(obj, t)), None)
        if t:
            _pack_ext(ext_handlers[t](obj), fp, options)
        else:
            raise UnsupportedTypeException(
                "unsupported type: %s" % str(type(obj)))
    else:
        raise UnsupportedTypeException(
            "unsupported type: %s" % str(type(obj)))


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
    data = fp.read(n)
    if len(data) < n:
        raise InsufficientDataException()
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
    raise Exception("logic error, not int: 0x%02x" % ord(code))


def _unpack_reserved(code, fp, options):
    if code == b'\xc1':
        raise ReservedCodeException(
            "encountered reserved code: 0x%02x" % ord(code))
    raise Exception(
        "logic error, not reserved code: 0x%02x" % ord(code))


def _unpack_nil(code, fp, options):
    if code == b'\xc0':
        return None
    raise Exception("logic error, not nil: 0x%02x" % ord(code))


def _unpack_boolean(code, fp, options):
    if code == b'\xc2':
        return False
    elif code == b'\xc3':
        return True
    raise Exception("logic error, not boolean: 0x%02x" % ord(code))


def _unpack_float(code, fp, options):
    if code == b'\xca':
        return struct.unpack(">f", _read_except(fp, 4))[0]
    elif code == b'\xcb':
        return struct.unpack(">d", _read_except(fp, 8))[0]
    raise Exception("logic error, not float: 0x%02x" % ord(code))


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
        raise Exception("logic error, not string: 0x%02x" % ord(code))

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
        raise Exception("logic error, not binary: 0x%02x" % ord(code))

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
        raise Exception("logic error, not ext: 0x%02x" % ord(code))

    ext = Ext(ord(_read_except(fp, 1)), _read_except(fp, length))

    # Unpack with ext handler, if we have one
    ext_handlers = options.get("ext_handlers")
    if ext_handlers and ext.type in ext_handlers:
        ext = ext_handlers[ext.type](ext)

    return ext


def _unpack_array(code, fp, options):
    if (ord(code) & 0xf0) == 0x90:
        length = (ord(code) & ~0xf0)
    elif code == b'\xdc':
        length = struct.unpack(">H", _read_except(fp, 2))[0]
    elif code == b'\xdd':
        length = struct.unpack(">I", _read_except(fp, 4))[0]
    else:
        raise Exception("logic error, not array: 0x%02x" % ord(code))

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
        raise Exception("logic error, not map: 0x%02x" % ord(code))

    d = {} if not options.get('use_ordered_dict') \
        else collections.OrderedDict()
    for _ in xrange(length):
        # Unpack key
        k = _unpack(fp, options)

        if isinstance(k, list):
            # Attempt to convert list into a hashable tuple
            k = _deep_list_to_tuple(k)
        elif not isinstance(k, collections.Hashable):
            raise UnhashableKeyException(
                "encountered unhashable key: %s, %s" % (str(k), str(type(k))))
        elif k in d:
            raise DuplicateKeyException(
                "encountered duplicate key: %s, %s" % (str(k), str(type(k))))

        # Unpack value
        v = _unpack(fp, options)

        try:
            d[k] = v
        except TypeError:
            raise UnhashableKeyException(
                "encountered unhashable key: %s" % str(k))
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
    global _float_precision
    global _unpack_dispatch_table
    global xrange

    # Compatibility mode for handling strings/bytes with the old specification
    compatibility = False

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
