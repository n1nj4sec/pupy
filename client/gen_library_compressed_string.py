#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import zipfile
import struct

from io import open


def get_encoded_library_string(filepath, out):
    dest = os.path.dirname(filepath)
    if not os.path.exists(dest):
        os.makedirs(dest)

    zip = zipfile.ZipFile(open(filepath, 'rb'))

    modules = dict([
        (
            z.filename, zip.open(z.filename,).read()
        ) for z in zip.infolist() if os.path.splitext(z.filename)[1] in (
            '.py', '.pyd', '.dll', '.pyc', '.pyo', '.so', '.toc'
        )
    ])

    ks = len(modules)
    out.write(struct.pack('>I', ks))
    for module in modules:
        content = modules[module]

        out.write(struct.pack('>II', len(module), len(content)))
        out.write(module.encode('utf8'))
        out.write(content)


with open(sys.argv[1], 'wb') as w:
    get_encoded_library_string(sys.argv[2], w)
