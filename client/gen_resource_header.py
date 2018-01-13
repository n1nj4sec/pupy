#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import binascii
import pylzma
import struct
import os

MAX_CHAR_PER_LINE=50

if __name__=="__main__":
    h_file=""
    file_bytes=b""
    output = os.path.basename(sys.argv[2]).replace('.', '_')

    with open(sys.argv[1], "rb") as f:
        file_bytes=f.read()

    compressed = int(sys.argv[3])

    attribute = ''
    pragma = ''

    if len(sys.argv) > 5:
        compiler = sys.argv[4]

        if compiler == 'cl':
            print "USING MSVC pragmas, const_seg: {}".format(sys.argv[5])
            attribute = '\n#pragma const_seg(push, stack1, "{}")\n'.format(sys.argv[5])
            pragma = '\n#pragma const_seg(pop, stack1)'
        else:
            attribute = '\n'.join([
                '__attribute__(({}))'.format(x) for x in sys.argv[5:]
            ])

    payload_len = len(file_bytes)
    payload = struct.pack('>I', payload_len) + (
        pylzma.compress(
            file_bytes, dictionary=24, fastBytes=255
        ) if compressed else file_bytes
    )

    h_file += "static const int %s_size = %s;"%(output, len(payload))
    h_file += attribute
    h_file += "\nstatic const char %s_start[] = {\n"%(output)
    current_size=0

    for c in payload:
        h_file+="'\\x%s',"%binascii.hexlify(c)
        current_size+=1
        if current_size>MAX_CHAR_PER_LINE:
            current_size=0
            h_file+="\n"

    h_file += "'\\x00' };\n"
    h_file += pragma

    with open(sys.argv[2],'w') as w:
        w.write(h_file)
