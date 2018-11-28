#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pefile


def get_pe_arch(*args, **kwargs):
    pe = None
    if args:
        pe = pefile.PE(args[0], fast_load=True)
    elif "data" in kwargs:
        pe = pefile.PE(data=kwargs["data"], fast_load=True)
    else:
        raise NameError("at least a path or data must be supplied to get_arch")
    if pe.OPTIONAL_HEADER.Magic == 0x010b:
        return "32bit"
    elif pe.OPTIONAL_HEADER.Magic == 0x020b:
        return "64bit"
    else:
        return "UNKNOWN"


def is_dotnet_bin(*args):
    pe = pefile.PE(args[0], fast_load=True)
    is_dotnet = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
    if is_dotnet.VirtualAddress == 0 and is_dotnet.Size == 0:
        return False
    else:
        return True
