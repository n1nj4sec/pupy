#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

import marshal, zlib, base64

def compress_encode_obfs(code):
    return "import zlib,base64,marshal;exec marshal.loads(zlib.decompress(base64.b64decode(%s)))"%repr(
        base64.b64encode(zlib.compress(marshal.dumps(compile(code, '', 'exec')), 9)))
