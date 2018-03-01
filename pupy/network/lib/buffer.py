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

    def __init__(self, data='', on_write=None, transport_func=None):
        """
        Initialize a buffer with 'data'.
        """
        self._buffer_bytes = BytesIO()
        self._buffer = ''
        self._len = 0
        self.on_write_f=on_write
        self.waiting_lock=threading.Lock()
        self.data_lock=threading.RLock()
        self.waiting=threading.Event()
        self.transport=transport_func
        self.cookie=None

    @property
    def buffer(self):
        if self._buffer_bytes.tell() > 0:
            if self._buffer:
                self._buffer += self._buffer_bytes.getvalue()
            else:
                self._buffer = self._buffer_bytes.getvalue()

            self._buffer_bytes.seek(0)
            self._buffer_bytes.truncate(0)

        return self._buffer

    def on_write(self):
        if self.on_write_f:
            self.on_write_f()

    def wait(self, timeout=0.1):
        """ wait for a size """
        if len(self.buffer)>0:
            return True
        else:
            self.waiting.clear()

        self.waiting.wait(timeout)
        return len(self.buffer)>0

    def wake(self):
        self.waiting.set()

    def read(self, n=-1):
        """
        Read and return 'n' bytes from the buffer.

        If 'n' is negative, read and return the whole buffer.
        If 'n' is larger than the size of the buffer, read and return
        the whole buffer.
        """

        with self.data_lock:
            if (n < 0) or (n > self._len):
                data = self.buffer
                self._buffer = ''
                self._len = 0
                return data

            if n <= len(self._buffer):
                data, self._buffer = self._buffer[:n], self._buffer[n:]
                self._len -= n
                return data

            data = self.buffer[:n]
            self._buffer = self._buffer[n:]
            self._len -= n

            return data

    def insert(self, data):
        if self._buffer:
            self._buffer = data + self._buffer
        else:
            self._buffer = data

    def write(self, data, notify=True):
        """
        Append 'data' to the buffer.
        """

        with self.data_lock:
            l = len(data)
            lb = len(self._buffer)
            lbb = self._buffer_bytes.tell()

            if not lbb and not lb and l < 2048:
                self._buffer = data
            elif not lbb and (lb+l) < 4096:
                self._buffer += data
            else:
                self._buffer_bytes.write(data)

            self._len += len(data)
            del data

            if notify:
                self.on_write()
                self.waiting.set()

    def flush(self):
        with self.data_lock:
            if self._len > 0:
                self.on_write()
                self.waiting.set()

    def write_to(self, stream, modificator=None, notify=True):
        with self.data_lock:
            forced_notify = True
            if hasattr(stream, 'flush'):
                forced_notify = False

            if self._buffer:
                data = self._buffer
                self._buffer = ''
                if modificator:
                    data = modificator(data)

                if not forced_notify:
                    stream.write(data, notify=False)
                else:
                    stream.write(data)

            blen = self._buffer_bytes.tell()
            self._buffer_bytes.seek(0)
            while blen > 0:
                data = self._buffer_bytes.read(4096)
                blen -= len(data)
                if modificator:
                    data = modificator(data)

                if not forced_notify:
                    stream.write(data, notify=False)
                else:
                    stream.write(data)

            self._buffer_bytes.seek(0)
            self._buffer_bytes.truncate(0)

            if notify and not forced_notify:
                stream.flush()

            print "DEBUG:", id(self), sys.getsizeof(self._buffer_bytes)

    def peek(self, n=-1):
        """
        Return 'n' bytes from the buffer, without draining them.

        If 'n' is negative, return the whole buffer.
        If 'n' is larger than the size of the buffer, return the whole
        buffer.
        """

        with self.data_lock:
            if (n < 0) or (n > self._len):
                return self.buffer

            if n <= len(self._buffer):
                return self._buffer[:n]

            return self.buffer[:n]

    def drain(self, n=-1):
        """
        Drain 'n' bytes from the buffer.

        If 'n' is negative, drain the whole buffer.
        If 'n' is larger than the size of the buffer, drain the whole
        buffer.
        """

        with self.data_lock:
            if (n < 0) or (n > len(self.buffer)):
                self._buffer = ''
                self._buffer_bytes.seek(0)
                self._buffer_bytes.truncate(0)
                self._len = 0
                return

            bl = len(self._buffer)

            if n <= bl:
                self._buffer = self._buffer[n:]
                self._len -= n
                return

            self._buffer = ''
            n -= bl

            self._buffer = self._buffer_bytes.getvalue()[n:]
            self._buffer_bytes.seek(0)
            self._buffer_bytes.truncate(0)
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
            return True if self._len else False
