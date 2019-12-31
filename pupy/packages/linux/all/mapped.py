# -*- coding: utf-8 -*-

try:
    from _pupy import pathmap
    from pupy._linux_memfd import (
        memfd_is_supported, memfd_create
    )

except ImportError:
    raise ValueError('PathMap not supproted')


if not memfd_is_supported():
    raise ValueError('Memfd is not supported')


MAPPED_FDS = {}


def create_mapped_file(path, data):
    if path in MAPPED_FDS:
        raise ValueError('Mapped file {} exists'.format(path))

    fd, filepath = memfd_create()

    pathmap[path] = filepath
    MAPPED_FDS[path] = fd

    fd.write(data)
    fd.flush()


def close_mapped_file(path):
    if path not in MAPPED_FDS:
        raise ValueError('File {} is not mapped'.format(path))

    MAPPED_FDS[path].close()

    del MAPPED_FDS[path]
    del pathmap[path]
