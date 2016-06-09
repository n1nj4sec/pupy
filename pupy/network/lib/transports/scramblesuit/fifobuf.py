"""
Provides an interface for a fast FIFO buffer.

The interface implements only 'read()', 'write()' and 'len()'.  The
implementation below is a modified version of the code originally written by
Ben Timby: http://ben.timby.com/?p=139
"""

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

MAX_BUFFER = 1024**2*4

class Buffer( object ):

    """
    Implements a fast FIFO buffer.

    Internally, the buffer consists of a list of StringIO objects.  New
    StringIO objects are added and delete as data is written to and read from
    the FIFO buffer.
    """

    def __init__( self, max_size=MAX_BUFFER ):
        """
        Initialise a Buffer object.
        """

        self.buffers = []
        self.max_size = max_size
        self.read_pos = 0
        self.write_pos = 0

    def write( self, data ):
        """
        Write `data' to the FIFO buffer.

        If necessary, a new internal buffer is created.
        """

        # Add a StringIO buffer if none exists yet.
        if not self.buffers:
            self.buffers.append(StringIO())
            self.write_pos = 0

        lastBuf = self.buffers[-1]
        lastBuf.seek(self.write_pos)
        lastBuf.write(data)

        # If we are over the limit, a new internal buffer is created.
        if lastBuf.tell() >= self.max_size:
            lastBuf = StringIO()
            self.buffers.append(lastBuf)

        self.write_pos = lastBuf.tell()

    def read( self, length=-1 ):
        """
        Read `length' elements of the FIFO buffer.

        Drained data is automatically deleted.
        """

        read_buf = StringIO()
        remaining = length

        while True:

            if not self.buffers:
                break

            firstBuf = self.buffers[0]
            firstBuf.seek(self.read_pos)
            read_buf.write(firstBuf.read(remaining))
            self.read_pos = firstBuf.tell()

            if length == -1:

                # We did not limit the read, we exhausted the buffer, so delete
                # it.  Keep reading from the remaining buffers.
                del self.buffers[0]
                self.read_pos = 0

            else:

                # We limited the read so either we exhausted the buffer or not.
                remaining = length - read_buf.tell()

                if remaining > 0:
                    # Exhausted, remove buffer, read more.  Keep reading from
                    # remaining buffers.
                    del self.buffers[0]
                    self.read_pos = 0
                else:
                    # Did not exhaust buffer, but read all that was requested.
                    # Break to stop reading and return data of requested
                    # length.
                    break

        return read_buf.getvalue()

    def __len__(self):
        """
        Return the length of the Buffer object.
        """

        length = 0

        for buf in self.buffers:

            # Jump to the end of the internal buffer.
            buf.seek(0, 2)

            if buf == self.buffers[0]:
                length += buf.tell() - self.read_pos
            else:
                length += buf.tell()

        return length
