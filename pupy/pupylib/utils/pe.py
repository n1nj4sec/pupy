#!/usr/bin/env python
# -*- coding: UTF8 -*-

import pefile

def get_pe_arch(*args, **kwargs):
    pe=None
    if args:
        pe = pefile.PE(args[0], fast_load=True)
    elif "data" in kwargs:
        pe = pefile.PE(data=kwargs["data"], fast_load=True)
    else:
        raise NameError("at least a path or data must be supplied to get_arch")
    if pe.OPTIONAL_HEADER.Magic==0x010b:
        return "32bit"
    elif pe.OPTIONAL_HEADER.Magic==0x020b:
        return "64bit"
    else:
        return "UNKNOWN"

