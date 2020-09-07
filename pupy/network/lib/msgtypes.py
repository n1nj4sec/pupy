# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

__all__ = (
    'MSG_TYPES_PACK', 'MSG_TYPES_UNPACK',
    'msgpack_exthook'
)

from collections import namedtuple

from network.conf import transports

from network.lib import Proxy
from network.lib.proxies import ProxyInfo
from network.lib.utils import HostInfo, TransportInfo
from network.lib.convcompat import as_unicode_string_deep
from network.lib.rpc.core.brine import (
    register_named_tuple as brine_register_named_tuple
)

from umsgpack import Ext, packb, unpackb


MSG_TYPES_PACK = {}
MSG_TYPES_UNPACK = {}

KNOWN_NAMED_TUPLES = (
    Proxy, ProxyInfo, HostInfo, TransportInfo
)


def register_named_tuple(code, ntype):
    MSG_TYPES_PACK[type] = lambda obj: Ext(
        code, packb(tuple(x for x in obj)))
    MSG_TYPES_UNPACK[code] = lambda obj: ntype(
        *unpackb(obj.data))

    brine_register_named_tuple(code, ntype)


def register_string(ntype, code, name):
    MSG_TYPES_PACK[ntype] = lambda obj: Ext(code, '')
    MSG_TYPES_UNPACK[code] = lambda obj: name


for idx, ntype in enumerate(KNOWN_NAMED_TUPLES):
    register_named_tuple(idx, ntype)

SPECIAL_TYPES_OFFT = len(KNOWN_NAMED_TUPLES)

for idx, name in enumerate(transports):
    register_string(idx, transports[name], name)


wrapext = namedtuple('Ext', ('code', 'data'))


def msgpack_exthook(code, data):
    if code in MSG_TYPES_UNPACK:
        obj = wrapext(code, data)
        return as_unicode_string_deep(MSG_TYPES_UNPACK[code](obj))
