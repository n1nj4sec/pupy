# -*- coding: utf-8 -*-

import struct
from io import BytesIO
from zlib import compress, crc32

PNG_FILTER = struct.pack('>B', 0)
MAGIC = struct.pack('>8B', 137, 80, 78, 71, 13, 10, 26, 10)

def bmp_to_png(data, width, height, compression=9, reverse=False):
    # From MSS
    line = width * 3

    iterator = xrange(height)
    if reverse:
        iterator = reversed(iterator)

    scanlines = BytesIO()

    for i,y in enumerate(iterator):
        scanlines.write(PNG_FILTER)
        scanlines.write(data[y * line:y * line + line])

    scanlines = scanlines.getvalue()

    # Header: size, marker, data, CRC32
    ihdr = [b'', b'IHDR', b'', b'']
    ihdr[2] = struct.pack('>2I5B', width, height, 8, 2, 0, 0, 0)
    ihdr[3] = struct.pack('>I', crc32(b''.join(ihdr[1:3])) & 0xffffffff)
    ihdr[0] = struct.pack('>I', len(ihdr[2]))

    # Data: size, marker, data, CRC32
    idat = [b'', b'IDAT', compress(scanlines, compression), b'']
    idat[3] = struct.pack('>I', crc32(b''.join(idat[1:3])) & 0xffffffff)
    idat[0] = struct.pack('>I', len(idat[2]))

    del scanlines

    # Footer: size, marker, None, CRC32
    iend = [b'', b'IEND', b'', b'']
    iend[3] = struct.pack('>I', crc32(iend[1]) & 0xffffffff)
    iend[0] = struct.pack('>I', len(iend[2]))

    output = BytesIO()
    output.write(MAGIC)
    for x in ihdr:
        output.write(x)
    del ihdr[:]

    for x in idat:
        output.write(x)
    del idat[:]

    for x in iend:
        output.write(x)
    del iend[:]

    return output.getvalue()
