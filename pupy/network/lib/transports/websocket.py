# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

""" This module contains an implementation of the 'websocket' transport for pupy.

    Lots of the WebSocket protocol code came from https://github.com/Pithikos/python-websocket-server
"""

__all__ = (
    'InvalidHTTPReq', 'MalformedData', 'MissingData',
    'paths', 'UA',
    'PupyWebSocketTransport',
    'PupyWebSocketClient', 'PupyWebSocketServer'
)

import time
import base64
import struct
import random
import string
import re

from hashlib import sha1
from network.lib.buffer import Buffer

from ..base import BasePupyTransport

from network.lib import getLogger
logger = getLogger('ws')

class InvalidHTTPReq(Exception):
    __slots__ = ()

class MalformedData(Exception):
    __slots__ = ()

class ShortRead(Exception):
    __slots__ = ()

# IOCs: These should change per engagement.
paths = [
    "/wsapp"
]

# Also update conf.py in network/transports/websocket/
UA = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36"

error_response_body="""<html><body><h1>It works!</h1>
<p>This is the default web page for this server.</p>
<p>The web server software is running but no content has been added, yet.</p>
</body></html>"""
error_response="HTTP/1.1 200 OK\r\n"
error_response+="Server: Apache\r\n"
error_response+="Content-Type: text/html; charset=utf-8\r\n"
error_response+="Content-Length: %s\r\n"%len(error_response_body)
error_response+="\r\n"
error_response+=error_response_body

UPGRADE_101_SUCCESS = 'HTTP/1.1 101 '
MASK_LEN = 4

FIN                 = 0x80
OPCODE              = 0x0f
MASKED              = 0x80
PAYLOAD_LEN         = 0x7f
PAYLOAD_LEN_EXT16   = 0x7e
PAYLOAD_LEN_EXT64   = 0x7f
PAYLOAD_LEN_MAX     = 18446744073709551616
OPCODE_CONTINUATION = 0x0
OPCODE_TEXT         = 0x1
OPCODE_BINARY       = 0x2
OPCODE_CLOSE_CONN   = 0x8
OPCODE_PING         = 0x9
OPCODE_PONG         = 0xA

class XOR(object):
    __slots__ = ('offset', 'key')

    def __init__(self, key):
        self.key = key
        self.offset = 0

    def strxor(self, data):
        ldata = len(data)
        key = self.key
        lkey = len(key)
        offset = self.offset

        result = bytearray(ldata)
        for idx in xrange(ldata):
            result[idx] = chr(ord(data[idx]) ^ ord(key[(offset+idx)%lkey]))

        self.offset += idx+1

        return result

def add_ws_encapsulation(data, output, mask=None, opcode=OPCODE_BINARY):
    payload_len = len(data)
    header = None
    mask_flag = MASKED if mask else 0

    if payload_len < PAYLOAD_LEN_EXT16:
        header = struct.pack('BB', opcode, payload_len | mask_flag)
    elif payload_len >= PAYLOAD_LEN_EXT16 and payload_len <= 65535:
        header = struct.pack(
            '>BBH', opcode, PAYLOAD_LEN_EXT16 | mask_flag, payload_len)
    elif payload_len < PAYLOAD_LEN_MAX:
        header = struct.pack(
            '>BBQ', opcode, PAYLOAD_LEN_EXT64 | mask_flag, payload_len)
    else:
        raise Exception('Message too large to send without fragmentation')

    modificator = None
    if mask:
        header += mask
        modificator = XOR(mask).strxor

    output.write(header, notify=False)
    data.write_to(output, modificator=modificator)
def remove_ws_encapsulation(data, output, buf, remainder, mask=None):
    if remainder:

        encoder = None
        if mask:
            encoder = XOR(mask).strxor

        _, total_write = data.write_to(buf, n=remainder, modificator=encoder)

        remainder -= total_write
        if not remainder:
            _, msg_len = buf.write_to(output)
            return msg_len, remainder, mask
        else:
            return 0, remainder, mask

    if len(data) < 2:
        # Header too short
        logger.debug('Short read / 1: %d', len(data))
        return 0, remainder, mask

    b1, b2 = struct.unpack('BB', data.peek(2))
    opcode = b1 & OPCODE
    masked = b2 & MASKED
    payload_len = b2 & PAYLOAD_LEN
    mask_len = MASK_LEN if masked else 0

    logger.debug('b1=%02x b2=%02x len=%d', b1, b2, payload_len)

    if not b1:
        raise EOFError('Client closed connection')
    elif opcode == OPCODE_CLOSE_CONN:
        raise EOFError('Client asked to close connection')
    elif opcode == OPCODE_CONTINUATION:
        raise EOFError('Continuation frames not currently supported')
    elif opcode == OPCODE_PING:
        raise EOFError('Pings not supported')
    elif opcode == OPCODE_PONG:
        raise EOFError('Pongs not supported')
    elif masked and not mask:
        raise EOFError('Masked message')

    if payload_len == PAYLOAD_LEN_EXT16:
        if len(data) < 2 + 2 + mask_len:
            # Header too short
            logger.debug('Header too short: %d < %d', len(data), 2 + 2 + mask_len)
            return 0, remainder, bool(mask_len)

        _, _, payload_len = struct.unpack('>BBH', data.read(4))

    elif payload_len == PAYLOAD_LEN_EXT64:
        if len(data) < 2 + 8 + mask_len:
            # Header too short
            logger.debug('Header too short: %d < %d', len(data), 2 + 8 + mask_len)
            return 0, remainder, bool(mask_len)

        _, _, payload_len = struct.unpack('>BBQ', data.read(10))
    else:
        if len(data) < 2 + mask_len:
            logger.debug('Header too short: %d < %d', len(data), 2 + mask_len)
            return 0, remainder, bool(mask_len)

        # payload_len is b2, drain b1, b2
        data.drain(2)

    encoder = None
    if mask_len:
        mask = data.read(mask_len)
        encoder = XOR(mask).strxor

    if len(data) >= payload_len:
        _, msg_len = data.write_to(
            output, modificator=encoder, n=payload_len)

        return msg_len, remainder, mask

    _, written = data.write_to(buf, modificator=encoder)
    remainder = payload_len - written
    return 0, remainder, mask

class PupyWebSocketTransport(BasePupyTransport):
    """
    Implements the http protocol transport for pupy.
    """
    __slots__ = ()

class PupyWebSocketClient(PupyWebSocketTransport):
    client = True
    path = random.choice(paths)
    socketkey = ''.join(random.sample(string.printable,16))
    mask = ''.join(random.sample(string.printable, MASK_LEN))
    user_agent = UA
    host = "www.example.com"
    upgraded = False

    __slots__ = (
        'path', 'user_agent', 'socketkey',
        'missing_bytes', 'decoded'
    )

    def __init__(self, *args, **kwargs):
        PupyWebSocketTransport.__init__(self, *args, **kwargs)

        self.missing_bytes = 0
        self.decoded = Buffer()
        self.host = kwargs.get(
            'host',
            'www.' + ''.join(random.sample(string.printable,16)) + '.net')

    def on_connect(self):
        payload = "%s %s HTTP/1.1\r\n" % ('GET', self.path)
        payload += "Host: %s\r\n" % (self.host)
        payload += "User-Agent: %s\r\n" % (self.user_agent)
        payload += "Upgrade: websocket\r\n"
        payload += "Connection: Upgrade\r\n"
        payload += "Sec-WebSocket-Key: %s\r\n" % (base64.b64encode(self.socketkey))
        payload += "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n"
        payload += "Sec-WebSocket-Version: 13\r\n\r\n"

        self.downstream.write(payload)

        time.sleep(1)

    def upstream_recv(self, data):
        """
            raw data to websocket frame
            Encoding Client -> Server
            mask the data
        """

        try:
            add_ws_encapsulation(data, self.downstream, self.mask)

        except Exception, e:
            raise EOFError(str(e))

    def downstream_recv(self, data):
        """
            Decoding Server -> Client
            Non masked messages
        """
        try:
            if not self.upgraded:
                #let's parse HTTP responses :
                d = data.peek(len(UPGRADE_101_SUCCESS))
                if len(d) < len(UPGRADE_101_SUCCESS):
                    # Short answer
                    logger.debug('Short answer (%s)', repr(d))
                    return
                elif d.startswith('HTTP/') and not d.startswith(UPGRADE_101_SUCCESS):
                    raise EOFError('Invalid response: {}'.format(repr(d)))

                d = data.peek()
                if '\r\n\r\n' not in d:
                    logger.debug('Incomplete header')
                    return

                EOFP = d.index('\r\n\r\n')
                data.drain(EOFP + 4)
                logger.debug('Connection upgraded')

                self.upgraded = True

            logger.debug('Parse ws messages')
            while data:
                msg_len, self.missing_bytes, _ = remove_ws_encapsulation(
                    data, self.upstream, self.decoded, self.missing_bytes
                )

                logger.debug('Parsed: %d, missing: %d, left: %d', msg_len, self.missing_bytes, len(data))

                if not msg_len:
                    break

        except Exception, e:
            raise EOFError(str(e))


class PupyWebSocketServer(PupyWebSocketTransport):
    client = False
    verify_user_agent = UA # set to the user agent to verify or None not to verify
    missing_bytes = 0
    decoded_len = 0
    mask = ''

    __slots__ = (
        'verify_user_agent', 'missing_bytes', 'upgraded', 'decoded', 'mask'
    )

    def __init__(self, *args, **kwargs):
        PupyWebSocketTransport.__init__(self, *args, **kwargs)
        self.upgraded = False
        self.mask = True
        self.decoded = Buffer()

    def calculate_response_key(self, key):
        GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
        hsh = sha1(key.encode() + GUID.encode())
        response_key = base64.b64encode(hsh.digest()).strip()
        return response_key.decode('ASCII')

    def bad_request(self, msg):
        logger.debug(msg)
        self.downstream.write(error_response)
        self.close(0)

    def upstream_recv(self, data):
        """
            Encoding server -> client messages
            Messsages shouldn't be masked
        """
        try:
            add_ws_encapsulation(data, self.downstream)

        except Exception as e:
            raise EOFError(str(e))

    def downstream_recv(self, data):
        """
            Decoding client -> server messages
            Message should be masked coming from client
        """

        if not self.upgraded:
            d = data.peek()
            # Handle HTTP GET requests, strip websocket keys, verify UA etc
            if not d.startswith('GET '):
                self.bad_request('Invalid HTTP method or data (%s)', repr(d))

            if '\r\n\r\n' not in d:
                logger.debug('Short read, incomplete header')
                return

            _, path, _ = d.split(' ', 2)
            if path not in paths:
                self.bad_request('Path does not match ({})!'.format(path))
                return

            key = re.search('\n[sS]ec-[wW]eb[sS]ocket-[kK]ey[\s]*:[\s]*(.*)\r\n', d)
            if key:
                key = key.group(1)
            else:
                self.bad_request('Unable to get WebSocketKey')
                return

            if self.verify_user_agent:
                ua = re.search('\n[uU]ser-[aA]gent:[\s]*(.*)\r\n', d)
                if ua:
                    ua = ua.group(1)
                else:
                    self.bad_request('No User-Agent provided')
                    return

                if ua != self.verify_user_agent:
                    self.bad_request('Bad User-Agent provided. May be counter-intel')
                    return

            payload = 'HTTP/1.1 101 Switching Protocols\r\n'
            payload += 'Upgrade: websocket\r\n'
            payload += 'Connection: Upgrade\r\n'
            payload += 'Sec-WebSocket-Accept: %s\r\n' % (self.calculate_response_key(key))
            payload += '\r\n'

            self.downstream.write(payload)
            self.upgraded = True

            data.drain(d.index('\r\n\r\n') + 4)

        while data:
            msg_len, self.missing_bytes, self.mask = remove_ws_encapsulation(
                data, self.upstream, self.decoded,
                self.missing_bytes, self.mask)

            logger.debug('Parsed: %d, missing: %d, left: %d', msg_len, self.missing_bytes, len(data))

            if not msg_len:
                break
