# Using the same buffer object as in obfsproxy to enhance compatibility
# some modifications brings to have waiting capabilities

import threading
import sys
import zlib

DEFAULT_FORCED_FLUSH_BUFFER_SIZE = 32768
DEFAULT_MAX_STR_SIZE = 4096

class Buffer(object):
    """
    A Buffer is a simple FIFO buffer. You write() stuff to it, and you
    read() them back. You can also peek() or drain() data.
    """

    ALLOW_BUFFER_AS_DATA = True

    def __init__(self, data='', on_write=None, transport_func=None, truncate=False,
                 chunk_size=None, compressed=False):
        """
        Initialize a buffer with 'data'.
        """
        self._data = []
        self._len = 0

        self._bofft = 0

        self.on_write_f = on_write
        self.data_lock = threading.RLock()
        self.waiting = threading.Event()
        self.transport = transport_func
        self.cookie = None
        self.chunk_size = None
        self.compressor = None
        if compressed:
            self.compressor = zlib.compressobj(
                compressed if type(compressed) is int else 9
            )

            if data:
                data = self.compressor.compress(data)

        if data:
            self._data.append(data)
            self._len += len(data)

    def __enter__(self):
        self.data_lock.acquire()

    def __exit__(self, *exc):
        self.data_lock.release()

    def copy(self):
        buf = Buffer()
        buf._data = list(self._data)
        buf._len = self._len
        buf._bofft = self._bofft
        return buf

    def on_write(self):
        if self.on_write_f:
            self.on_write_f()

        self.waiting.set()

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

    def _linearize(self, upto=None):
        if upto is None:
            upto = self._len

        if len(self._data) < 2 or upto <= len(self._data[0]) - self._bofft:
            return

        free = 0
        to_alloc = 0

        # Estimate size:
        for idx, chunk in enumerate(self._data):
            lchunk = len(chunk)
            if idx == 0 and self._bofft > 0:
                lchunk -= self._bofft

            to_alloc += lchunk
            if to_alloc >= upto:
                break

        upto = to_alloc

        linearized = bytearray(upto)
        offset = 0

        for idx, chunk in enumerate(self._data):
            lchunk = len(chunk)

            if idx == 0 and self._bofft > 0:
                lchunk -= self._bofft
                linearized[offset:offset + lchunk] = chunk[self._bofft:]
                self._bofft = 0
            else:
                linearized[offset:offset+lchunk] = chunk

            self._data[idx] = None

            free += 1
            upto -= lchunk
            offset += lchunk

            if not upto:
                break

        self._data[0] = linearized

        if free:
            del self._data[1:free]

    def _obtain(self, n=-1, view=False, release=False):
        """
        Return 'n' bytes from the buffer, without draining them.

        If 'n' is negative, return the whole buffer.
        If 'n' is larger than the size of the buffer, return the whole
        buffer.
        """

        if not self._len:
            return ''

        elif n < 0 or n > self._len:
            n = self._len

        if n == 0:
            return ''

        mdata = None

        self._linearize(upto=n)

        if view:
            try:
                mdata = memoryview(self._data[0])[self._bofft:self._bofft+n]
            except TypeError:
                # Fallback
                mdata = bytes(self._data[0][self._bofft:self._bofft+n])
        else:
            mdata = bytes(self._data[0][self._bofft:self._bofft+n])

        if release:
            if self._bofft+n == len(self._data[0]):
                del self._data[0]
                self._bofft = 0
            else:
                self._bofft += n

            self._len -= n

        return mdata

    def read(self, n=-1, view=False):
        """
        Read and return 'n' bytes from the buffer.

        If 'n' is negative, read and return the whole buffer.
        If 'n' is larger than the size of the buffer, read and return
        the whole buffer.
        """

        with self.data_lock:
            # print "BREAD", id(self), n
            return self._obtain(n, view, True)

    def insert(self, data):
        with self.data_lock:
            if self.compressor:
                raise ValueError('Insert is not supported for compressed buffers')

            ldata = len(data)
            if self._bofft:
                if type(self._data[0]) in (bytearray, memoryview) and ldata <= self._bofft:
                    new_bofft = self._bofft - ldata
                    self._data[0][new_bofft:self._bofft] = data
                    self._bofft = new_bofft
                else:
                    newelem = bytearray(len(self._data[0])-self._bofft+ldata)
                    newelem[:ldata] = data
                    newelem[ldata:] = self._data[0][self._bofft:]
                    self._data[0] = newelem
                    self._bofft = 0
            else:
                self._data.insert(0, data)

            self._len += ldata

    def _truncate(self, newlen):
        if self._len == newlen:
            return

        if newlen < 0:
            newlen = self._len + newlen

        if newlen <= 0:
            del self._data[:]
            self._len = 0

        elif self._len < newlen:
            self._data.append(b'\x00'*(newlen - self._len))
            self._len = newlen

        else:
            lendiff = self._len - newlen
            while lendiff:
                clen = len(self._data[-1])
                offt = 0

                print self._data[-1], offt, clen, lendiff

                if len(self._data) == 1:
                    offt = self._bofft
                    clen -= offt

                if clen <= lendiff:
                    del self._data[-1]
                    lendiff -= clen
                else:
                    newchunklen = clen - lendiff
                    self._data[-1] = self._data[-1][offt:offt+newchunklen]
                    if offt:
                        self._bofft -= offt

                    lendiff = 0

            self._len = newlen

    def truncate(self, newlen):
        with self.data_lock:
            self._truncate(newlen)

    def _append(self, data):
        if not data:
            return

        if isinstance(data, Buffer):
            if self.compressor:
                for chunk in data._data:
                    chunk = self.compressor.compress(chunk)
                    self._data.append(chunk)
                    self._len += len(chunk)
            else:
                self._data += data._data
                self._len += data._len
        elif type(data) in (tuple, list):
            for chunk in data:
                if self.compressor:
                    chunk = self.compressor.compress(chunk)

                self._data.append(chunk)
                self._len += len(chunk)
        else:
            if self.compressor:
                data = self.compressor.compress(data)

            if self._len and type(self._data[-1]) == type(data) and \
              len(self._data[-1]) + len(data) <= DEFAULT_MAX_STR_SIZE:
                self._data[-1] += data
            else:
                self._data.append(data)

            self._len += len(data)

    def append(self, data):
        with self.data_lock:
            self._append(data)

    def write(self, data, notify=True):
        """
        Append 'data' to the buffer.
        """

        with self.data_lock:
            # print "BWRITE", id(self), len(data)
            self._append(data)

        if notify:
            self.on_write()

    def flush(self):
        if self.compressor:
            chunk = self.compressor.flush()
            self._data.append(chunk)
            self._len += len(chunk)

        if self._len > 0:
            self.on_write()

    def write_to(self, stream, modificator=None, notify=True, view=False, chunk_size=None, full_chunks=False):
        with self.data_lock:
            chunk_size = chunk_size or self.chunk_size
            total_write = 0

            forced_notify = True
            if hasattr(stream, 'flush'):
                forced_notify = False
            else:
                # Some old style thing, will copy anyway
                view = True

            if not forced_notify and not chunk_size:
                for idx, chunk in enumerate(self._data):
                    if idx == 0 and self._bofft:
                        chunk = chunk[self._bofft:]
                        self._bofft = 0

                    if modificator:
                        chunk = modificator(bytes(chunk))

                    stream.write(chunk, notify=False)
                    total_write += len(chunk)

                self._len = 0
                del self._data[:]
            else:
                # Old style interface. Better to send by big portions

                if not chunk_size:
                    chunk_size = DEFAULT_FORCED_FLUSH_BUFFER_SIZE

                while self._len:
                    if full_chunks and self._len < chunk_size:
                        break

                    chunk = self._obtain(
                        chunk_size,
                        release=True, view=not modificator)

                    if modificator:
                        chunk = modificator(chunk)

                    if forced_notify:
                        stream.write(chunk)
                    else:
                        stream.write(chunk, notify=False)

                    total_write += len(chunk)

        if notify and not forced_notify:
            stream.flush()

        return total_write

    def peek(self, n=-1, view=False):
        """
        Return 'n' bytes from the buffer, without draining them.

        If 'n' is negative, return the whole buffer.
        If 'n' is larger than the size of the buffer, return the whole
        buffer.
        """

        with self.data_lock:
            return self._obtain(n, view)

    def drain(self, n=-1):
        """
        Drain 'n' bytes from the buffer.

        If 'n' is negative, drain the whole buffer.
        If 'n' is larger than the size of the buffer, drain the whole
        buffer.
        """

        with self.data_lock:
            if n < 0 or n > self._len:
                n = self._len

            if n == 0:
                return

            elif n == self._len:
                del self._data[:]
                self._len = 0
                self._bofft = 0

            elif n < len(self._data[0]) - self._bofft:
                self._bofft += n
                self._len -= n
            else:
                todel = 0
                for idx, chunk in enumerate(self._data):
                    lchunk = len(chunk)
                    if idx == 0 and self._bofft:
                        lchunk -= self._bofft

                    if n >= lchunk:
                        self._len -= lchunk
                        self._bofft = 0

                        todel += 1
                        n -= lchunk
                    else:
                        self._bofft = n
                        self._len -= n
                        break

                del self._data[:todel]

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
