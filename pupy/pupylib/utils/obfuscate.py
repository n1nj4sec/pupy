#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

import marshal, zlib

def compress_encode_obfs(code):
    return "import zlib,marshal;exec marshal.loads(zlib.decompress(%s))"%repr(
        zlib.compress(marshal.dumps(compile(code, '', 'exec')), 9))
