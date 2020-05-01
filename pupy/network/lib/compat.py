'''
compatibility module for various versions of python (2.4/3+/jython)
and various platforms (posix/windows)
'''

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

__all__ = (
    'is_py3k', 'maxint',
    'Struct', 'BytesIO', 'pickle', 'callable',
    'select_module', 'select', 'get_exc_errno',
    'select_error', 'poll', 'xrange',
    'is_str', 'is_int', 'is_bin',
    'as_byte'
)


import sys
import time

is_py3k = (sys.version_info[0] >= 3)


if is_py3k:
    exec('execute = exec')

    maxint = sys.maxsize
    xrange = range

    def is_int(value):
        return isinstance(value, int)

    def is_str(value):
        return isinstance(value, str)

    def as_byte(value):
        return bytes((value,))

else:
    from __builtin__ import xrange

    exec('''def execute(code, globals = None, locals = None):
                exec code in globals, locals''')

    maxint = sys.maxsize

    def is_int(value):
        return isinstance(value, (int, long))

    def is_str(value):
        return isinstance(value, basestring)

    def as_byte(value):
        return chr(value)


def is_bin(value):
    return isinstance(value, (bytes, bytearray, memoryview))


try:
    from struct import Struct

except ImportError:
    import struct

    class Struct(object):

        __slots__ = ('format', 'size')

        def __init__(self, format):
            self.format = format
            self.size = struct.calcsize(format)

        def pack(self, *args):
            return struct.pack(self.format, *args)

        def unpack(self, data):
            return struct.unpack(self.format, data)


try:
    from cStringIO import StringIO as BytesIO
except ImportError:
    from io import BytesIO


try:
    next = next
except NameError:
    def next(iterator):
        return iterator.next()

try:
    import cPickle as pickle
except ImportError:
    import pickle

try:
    callable = callable
except NameError:
    def callable(obj):
        return hasattr(obj, '__call__')

try:
    import select as select_module
except ImportError:
    select_module = None

    def select(*args):
        raise ImportError('select not supported on this platform')

else:
    # jython
    if hasattr(select_module, 'cpython_compatible_select'):
        from select import cpython_compatible_select as select
    else:
        from select import select


def get_exc_errno(exc):
    if hasattr(exc, 'errno'):
        return exc.errno
    else:
        return exc[0]


if select_module:
    select_error = select_module.error
else:
    select_error = IOError


if hasattr(select_module, 'poll'):

    class PollingPoll(object):
        def __init__(self):
            self._poll = select_module.poll()

        def register(self, fd, mode):
            flags = 0
            if 'r' in mode:
                flags |= select_module.POLLIN | select_module.POLLPRI
            if 'w' in mode:
                flags |= select_module.POLLOUT
            if 'e' in mode:
                flags |= select_module.POLLERR
            if 'h' in mode:
                # POLLRDHUP is a linux only extension, not known to python, but nevertheless
                # used and thus needed in the flags
                POLLRDHUP = 0x2000
                flags |= select_module.POLLHUP | select_module.POLLNVAL | POLLRDHUP

            self._poll.register(fd, flags)

        modify = register

        def unregister(self, fd):
            self._poll.unregister(fd)

        def poll(self, timeout = None):
            if timeout:
                # the real poll takes milliseconds while we have seconds here
                timeout = 1000*timeout

            events = self._poll.poll(timeout)
            processed = []

            for fd, evt in events:
                mask = ''
                if evt & (select_module.POLLIN | select_module.POLLPRI):
                    mask += 'r'
                if evt & select_module.POLLOUT:
                    mask += 'w'
                if evt & select_module.POLLERR:
                    mask += 'e'
                if evt & select_module.POLLHUP:
                    mask += 'h'
                if evt & select_module.POLLNVAL:
                    mask += 'n'
                processed.append((fd, mask))
            return processed

    poll = PollingPoll

else:
    class SelectingPoll(object):

        def __init__(self):
            self.rlist = set()
            self.wlist = set()

        def register(self, fd, mode):
            if 'r' in mode:
                self.rlist.add(fd)
            if 'w' in mode:
                self.wlist.add(fd)

        modify = register

        def unregister(self, fd):
            self.rlist.discard(fd)
            self.wlist.discard(fd)

        def poll(self, timeout = None):
            if not self.rlist and not self.wlist:
                time.sleep(timeout)
                return []  # need to return an empty array in this case
            else:
                rl, wl, _ = select(self.rlist, self.wlist, (), timeout)
                return [(fd, 'r') for fd in rl] + [(fd, 'w') for fd in wl]

    poll = SelectingPoll



# From six.py

def with_metaclass(meta, *bases):
    ''' Create a base class with a metaclass. '''
    # This requires a bit of explanation: the basic idea is to make a dummy
    # metaclass for one level of class instantiation that replaces itself with
    # the actual metaclass.
    class metaclass(type):

        def __new__(cls, name, this_bases, d):
            return meta(name, bases, d)

        @classmethod
        def __prepare__(cls, name, this_bases):
            return meta.__prepare__(name, bases)

    return type.__new__(
        metaclass,
        str('temporary_class'), (), {}
    )
