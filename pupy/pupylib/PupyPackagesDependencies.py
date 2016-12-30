#!/usr/bin/env python
# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

LOAD_PACKAGE=1
LOAD_DLL=2
EXEC=3

ALL_OS=1
WINDOWS=2
LINUX=4
ANDROID=8

# dependencies to load for each modules
packages_dependencies={

    "pupwinutils.memexec" : [
        (LOAD_PACKAGE, ALL_OS, "pupymemexec"),
    ],
    "memorpy" : [
        (LOAD_PACKAGE, WINDOWS, "win32api"),
        (LOAD_PACKAGE, WINDOWS, "win32security"),
    ],
    "scapy" : [
        (LOAD_PACKAGE, ALL_OS, "gzip"),
        (LOAD_PACKAGE, ALL_OS, "_strptime"),
        (LOAD_PACKAGE, ALL_OS, "calendar"),
    ],
    "pyaudio" : [
        (LOAD_PACKAGE, ALL_OS, "_portaudio"),
    ],
    "scapy" : [
        (LOAD_PACKAGE, ALL_OS, "gzip"),
        (LOAD_PACKAGE, ALL_OS, "_strptime"),
        (LOAD_PACKAGE, ALL_OS, "calendar"),
    ],
    "OpenSSL" : [
        (LOAD_PACKAGE, ALL_OS, "six"),
        (LOAD_PACKAGE, ALL_OS, "enum"),
        (LOAD_PACKAGE, ALL_OS, "cryptography"),
        (LOAD_PACKAGE, ALL_OS, "_cffi_backend"),
        (LOAD_PACKAGE, ALL_OS, "plistlib"),
        (LOAD_PACKAGE, ALL_OS, "uu"),
        (LOAD_PACKAGE, ALL_OS, "quopri"),
        (LOAD_PACKAGE, ALL_OS, "pyparsing"),
        (LOAD_PACKAGE, ALL_OS, "pkg_resources"),
        (LOAD_PACKAGE, ALL_OS, "pprint"),
        (LOAD_PACKAGE, ALL_OS, "ipaddress"),
        (LOAD_PACKAGE, ALL_OS, "idna"),
        (LOAD_PACKAGE, ALL_OS, "unicodedata"),
    ],


}
