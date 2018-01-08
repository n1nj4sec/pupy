# -*- coding: utf-8 -*-

import string

def ascii85EncodeDG(str):
    "Encode a string according to ASCII-Base-85."

    result = ''
    fetched = 0

    while 1:
        buf = map(lambda x:ord(x)+0L, str[fetched:fetched+4])
        fetched = fetched + len(buf)

        if not buf:
            break

        while fetched % 4:
            buf.append(0)
            fetched = fetched + 1

        num = (buf[0] << 24) + (buf[1] << 16) + (buf[2] << 8) + buf[3]
        if num == 0:
            return 'z'

        res = [0] * 5
        for i in (4, 3, 2, 1, 0):
            res[i] = ord('!') + num % 85
            num = num / 85

        res = res[:len(str)+1]
        result = result + string.join(map(chr, res), '')

    return result + "~>"


def ascii85DecodeDG(str):
    "Decode a string encoded with ASCII-Base-85."

    str = string.join(string.split(str),'')
    msg = 'Invalid terminator for Ascii Base 85 Stream'
    assert str[-2:] == '~>', msg
    str = str[:-2]

    #may have 'z' in it which complicates matters - expand them
    str = string.replace(str, 'z', '!!!!!')

    result = ''
    fetched = 0

    while 1:
        buf = map(lambda x:ord(x)+0L-33, str[fetched:fetched+5])
        fetched = fetched + len(buf)

        if not buf:
            break

        while fetched % 5:
            buf.append(0)
            fetched = fetched + 1

        c1, c2, c3, c4, c5 = buf
        num = ((85**4) * c1) + ((85**3) * c2) + ((85**2) * c3) + (85*c4) + c5

        temp, b4 = divmod(num, 256)
        temp, b3 = divmod(temp, 256)
        b1, b2 = divmod(temp, 256)

        assert num == 16777216 * b1 + 65536 * b2 + 256 * b3 + b4, 'dodgy code!'
        # This modulo operation (256) is maybe a hack! DCG
        res = b1%256, b2, b3, b4
        result = result + string.join(map(chr, res), '')

    return result
