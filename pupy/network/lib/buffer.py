# Using the same buffer object as in obfsproxy to enhance compatibility
#some modifications brings to have waiting capabilities
import threading
import sys
from io import BytesIO, DEFAULT_BUFFER_SIZE

class Buffer(object):
    """
    A Buffer is a simple FIFO buffer. You write() stuff to it, and you
    read() them back. You can also peek() or drain() data.
    """

    def __init__(self, data='', on_write=None, transport_func=None, preallocate=None, truncate=False):
        """
        Initialize a buffer with 'data'.
        """
        self._buffer_bytes = BytesIO()
        self._preallocate = preallocate = 0
        if preallocate:
            self._buffer_bytes.seek(preallocate)
            self._buffer_bytes.write('\0')
            self._buffer_bytes.seek(0)
            self._preallocate = preallocate

        self._buffer = ''
        self._len = 0
        self._bofft = 0
        self.on_write_f=on_write
        self.waiting_lock=threading.Lock()
        self.data_lock=threading.RLock()
        self.waiting=threading.Event()
        self.transport=transport_func
        self.cookie=None

    def _linearize(self):
        bpos = self._buffer_bytes.tell()
        if bpos > 0:
            self._buffer_bytes.seek(self._bofft)
            data = self._buffer_bytes.read(bpos-self._bofft)
            self._buffer_bytes.seek(0)
            self._buffer_bytes.truncate(self._preallocate)
            self._bofft = 0

            #print "LINEARIZE:", id(self), len(data), self._buffer_bytes.tell(), self._len

            if self._buffer:
                self._buffer += data
            else:
                self._buffer = data

        return self._buffer

    @property
    def buffer(self):
        with self.data_lock:
            return self._linearize()

    def on_write(self):
        if self.on_write_f:
            self.on_write_f()

    def wait(self, timeout=0.1):
        """ wait for a size """
        if self._len > 0:
            return True
        else:
            self.waiting.clear()

        self.waiting.wait(timeout)
        return self._len > 0

    def wake(self):
        self.waiting.set()

    def read(self, n=-1):
        """
        Read and return 'n' bytes from the buffer.

        If 'n' is negative, read and return the whole buffer.
        If 'n' is larger than the size of the buffer, read and return
        the whole buffer.
        """

        #print "READ", n, id(self), self._len
        with self.data_lock:
            #print "READ", n, id(self), "ACQ LOCK"
            if (n < 0) or (n >= self._len):
                #print "READ #1"
                self._linearize()
                data = self._buffer
                self._buffer = ''
                self._len = 0

                #print "READ RES", id(self), len(data), data.encode('hex')
                return data

            if n <= len(self._buffer):
                #print "READ #2", id(self), n, len(self._buffer), self._len
                data = self._buffer[:n]
                self._buffer = self._buffer[n:]
                self._len -= n
                #print "READ RES", id(self), len(data), data.encode('hex')
                return data

            #print "READ #3", id(self), n, self._len, self._bofft

            data = self._buffer
            ldata = len(data)

            self._buffer = ''
            n -= ldata
            self._len -= ldata

            cpos = self._buffer_bytes.tell()

            self._buffer_bytes.seek(self._bofft)
            data += self._buffer_bytes.read(n)
            self._bofft += n
            self._len   -= n
            self._buffer_bytes.seek(cpos)

            #print "READ RES", id(self), len(data), data.encode('hex'), self._bofft, self._len
            return data

    def insert(self, data):
        #print "INSERT", len(data), id(self)

        with self.data_lock:
            #print "INSERT", len(data), id(self), "ACQ LOCK"
            if self._buffer:
                self._buffer = data + self._buffer
            else:
                self._buffer = data

            self._len += len(data)

    def write(self, data, notify=True):
        """
        Append 'data' to the buffer.
        """

        #print "WRITE", len(data), id(self), data.encode('hex')

        with self.data_lock:
            #print "WRITE ACQ LOCK", len(data), id(self)

            l = len(data)
            lb = len(self._buffer)
            lbb = self._buffer_bytes.tell() - self._bofft

            if not lbb and not lb and l < 2048:
                self._buffer = data
            elif not lbb and (lb+l) < DEFAULT_BUFFER_SIZE:
                self._buffer += data
            else:
                self._buffer_bytes.write(data)

            self._len += l
            del data

            if notify:
                #print "WRITE NOTIFY", id(self)
                self.on_write()
                self.waiting.set()
                #print "WRITE NOTIFY COMPLETE", id(self)
            # else:
                #print "WRITE NO NOTIFY COMPLETE", id(self)

    def flush(self):
        #print "FLUSH", id(self)

        with self.data_lock:
            #print "FLUSH ACQ LOCK", id(self)
            if self._len > 0:
                self.on_write()
                self.waiting.set()
            #print "FLUSH COMPLETE", id(self)

    def write_to(self, stream, modificator=None, notify=True):
        #print "WRITE TO", id(self), id(stream), self._len
        with self.data_lock:
            #print "WRITE TO", id(self), id(stream), "ACQ LOCK"
            forced_notify = True
            if hasattr(stream, 'flush'):
                forced_notify = False

            if self._buffer:
                data = self._buffer
                self._buffer = ''
                self._len -= len(data)

                if modificator:
                    data = modificator(data)

                if not forced_notify:
                    stream.write(data, notify=False)
                else:
                    stream.write(data)

            self._buffer_bytes.seek(self._bofft)
            while self._len > 0:
                data = self._buffer_bytes.read(min(self._len, DEFAULT_BUFFER_SIZE))
                self._len -= len(data)

                if modificator:
                    data = modificator(data)

                if not forced_notify:
                    stream.write(data, notify=False)
                else:
                    stream.write(data)

            self._buffer_bytes.seek(0)
            self._bofft = 0

            if notify and not forced_notify:
                #print "FLUSH...", id(stream)
                stream.flush()
                #print "...FLUSH OK", id(stream)
            # else:
                #print "WRITE TO COMPLETED (NOFLUSH)", id(self), id(stream), notify


    def peek(self, n=-1):
        """
        Return 'n' bytes from the buffer, without draining them.

        If 'n' is negative, return the whole buffer.
        If 'n' is larger than the size of the buffer, return the whole
        buffer.
        """

        #print "PEEK", n, id(self), self._len
        with self.data_lock:
            #print "PEEK", n, id(self), "LOCKED"
            if (n < 0) or (n >= self._len):
                return self._linearize()

            if n <= len(self._buffer):
                return self._buffer[:n]

            self._linearize()
            return self._buffer[:n]

    def drain(self, n=-1):
        """
        Drain 'n' bytes from the buffer.

        If 'n' is negative, drain the whole buffer.
        If 'n' is larger than the size of the buffer, drain the whole
        buffer.
        """

        #print "DRAIN", n, id(self)

        with self.data_lock:
            if (n < 0) or (n >= self._len):
                self._buffer = ''
                self._buffer_bytes.seek(self._bofft)
                self._len = 0
                return

            bl = len(self._buffer)

            if n <= bl:
                self._buffer = self._buffer[n:]
                self._len -= n
                return

            self._buffer = ''
            n -= bl
            self._len -= bl

            self._bofft = n
            self._len -= n

            return

    def __len__(self):
        """Returns length of buffer. Used in len()."""
        with self.data_lock:
            return self._len

    def __nonzero__(self):
        """
        Returns True if the buffer is non-empty.
        Used in truth-value testing.
        """
        with self.data_lock:
            return bool(self._len)
