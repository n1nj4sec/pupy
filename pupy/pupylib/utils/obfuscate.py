#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

import zlib
from pupylib.PupyCompile import pupycompile

def compress_encode_obfs(code, main=False):
    return "import zlib,marshal;exec marshal.loads(zlib.decompress(%s))"%repr(
        zlib.compress(pupycompile(code, main=main, raw=True), 9))
