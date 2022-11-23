#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file
# at the root of the project for the detailed licence terms

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import zlib

from pupy.pupylib.PupyCompile import pupycompile


# FIXME

def compress_encode_obfs(code, main=False, py=True):
    if py:
        # compatible version without compiling bytecode
        data = zlib.compress(code.encode('utf8'), 9)
        formatted = '('
        for i in range(0, len(data), 100):
            formatted+="%s\n"%repr(data[i:i+100])
        formatted += ")"
        return 'import zlib;exec(zlib.decompress(%s).decode("utf8"))'%formatted
    else:
        return 'import zlib,marshal;exec(marshal.loads(zlib.decompress(%s)))' % repr(
            zlib.compress(pupycompile(code, main=main, raw=True), 9)
        )
