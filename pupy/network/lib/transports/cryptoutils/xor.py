# -*- coding: utf-8 -*-

class XOR(object):
    __slots__ = ('offset', 'key')

    def __init__(self, key, offset=0):
        if not isinstance(key, bytes):
            key = key.encode('latin1')

        self.key = bytearray(key)
        self.offset = offset

    def strxor(self, data):
        key = self.key
        lkey = len(key)
        ldata = len(data)
        offset = self.offset

        result = bytearray(ldata)

        if ldata and not isinstance(data[0], int):
            if isinstance(data, bytes):
                data = bytearray(data)
            else:
                data = bytearray(data.encode('latin1'))

        for idx, c1 in enumerate(data):
            result[idx] = c1 ^ key[(offset+idx) % lkey]

        self.offset += idx+1
        return result
