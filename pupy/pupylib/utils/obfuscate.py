#!/usr/bin/env python
# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
import base64, zlib

def compress_encode_obfs(code):
    return "import base64,zlib;exec zlib.decompress(base64.b64decode(%s))"%repr(base64.b64encode(zlib.compress(code+"\n")))

