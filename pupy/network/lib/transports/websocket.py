# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms

""" This module contains an implementation of the 'websocket' transport for pupy.

    Lots of the WebSocket protocol code came from https://github.com/Pithikos/python-websocket-server
"""

__all__ = (
    'InvalidHTTPReq', 'PupyWebSocketTransport',
    'PupyWebSocketClient', 'PupyWebSocketServer'
)

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

    def __init__(self, key, offset=0):
        self.key = key
        self.offset = offset

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

def remove_ws_encapsulation(data, output, buf, offset, remainder, mask=None):
    if remainder:

        encoder = None
        modificator = None
        if mask:
            encoder = XOR(mask, offset)
            modificator = encoder.strxor

        _, total_write = data.write_to(
            buf, n=remainder, modificator=modificator)

        remainder -= total_write
        if not remainder:
            _, msg_len = buf.write_to(output)
            return msg_len, encoder.offset if encoder else 0, remainder, mask
        else:
            return 0, encoder.offset if encoder else 0, remainder, mask

    if len(data) < 2:
        # Header too short
        if __debug__:
            logger.debug('Short read / 1: %d', len(data))

        return 0, offset, remainder, mask

    b1, b2 = struct.unpack('BB', data.peek(2))
    opcode = b1 & OPCODE
    masked = b2 & MASKED
    payload_len = b2 & PAYLOAD_LEN
    mask_len = MASK_LEN if masked else 0

    if __debug__:
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
            if __debug__:
                logger.debug('Header too short: %d < %d', len(data), 2 + 2 + mask_len)
            return 0, offset, remainder, bool(mask_len)

        _, _, payload_len = struct.unpack('>BBH', data.read(4))

    elif payload_len == PAYLOAD_LEN_EXT64:
        if len(data) < 2 + 8 + mask_len:
            # Header too short
            if __debug__:
                logger.debug('Header too short: %d < %d', len(data), 2 + 8 + mask_len)
            return 0, offset, remainder, bool(mask_len)

        _, _, payload_len = struct.unpack('>BBQ', data.read(10))
    else:
        if len(data) < 2 + mask_len:
            if __debug__:
                logger.debug('Header too short: %d < %d', len(data), 2 + mask_len)
            return 0, offset, remainder, bool(mask_len)

        # payload_len is b2, drain b1, b2
        data.drain(2)

    encoder = None
    modificator = None
    if mask_len:
        mask = data.read(mask_len)
        encoder = XOR(mask)
        modificator = encoder.strxor

    if len(data) >= payload_len:
        _, msg_len = data.write_to(
            output, modificator=modificator, n=payload_len)

        return msg_len, encoder.offset if encoder else 0, remainder, mask

    _, written = data.write_to(buf, modificator=modificator)
    remainder = payload_len - written
    return 0, encoder.offset if encoder else 0, remainder, mask

class PupyWebSocketTransport(BasePupyTransport):
    """
    Implements the http protocol transport for pupy.
    """
    __slots__ = ()

class PupyWebSocketClient(PupyWebSocketTransport):
    socketkey = ''.join(random.sample(string.printable,16))

    __slots__ = (
        'host', 'path', 'user_agent', 'socketkey', 'offset',
        'missing_bytes', 'decoded', 'upgraded', 'mask',
        'connect', 'proxy', 'auth', 'upgraded_buf'
    )

    def __init__(self, *args, **kwargs):
        PupyWebSocketTransport.__init__(self, *args, **kwargs)

        self.upgraded = False
        self.missing_bytes = 0
        self.offset = 0
        self.decoded = Buffer()
        self.upgraded_buf = Buffer()
        self.user_agent = kwargs.get('user-agent')
        self.path = kwargs.get('path')
        self.connect = kwargs.get('connect', None)

        self.proxy = kwargs.get('proxy', False)
        self.auth = kwargs.get('auth', None)
        self.host = kwargs.get('host', None)

        if self.connect is None and self.host is not None:
            if ':' in self.host:
                host, port = self.host.rsplit(':', 1)
                port = int(port)
                self.connect = host, port
            else:
                self.connect = self.host, 80

        if self.host is None:
            self.host = 'www.' + ''.join(
                random.sample(string.lowercase + '.-',16)) + '.net'

        if __debug__:
            logger.debug(
                'WS Client, path=%s, user-agent=%s host=%s',
                self.path, self.user_agent, self.host)

    def on_connect(self):
        uri = self.path
        if self.proxy and self.connect:
            host, port = self.connect
            if port != 80:
                uri = ':' + str(port) + uri

            uri = 'http://' + host + uri

        payload = "%s %s HTTP/1.1\r\n" % ('GET', uri)
        payload += "Host: %s\r\n" % (self.host)
        payload += "User-Agent: %s\r\n" % (self.user_agent)
        payload += "Upgrade: websocket\r\n"
        payload += "Connection: Upgrade\r\n"

        if self.proxy and self.auth:
            payload += 'Proxy-Authorization: Basic ' + \
              base64.b64encode('{}:{}'.format(*self.auth))

        payload += "Sec-WebSocket-Key: %s\r\n" % (base64.b64encode(self.socketkey))
        payload += "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n"
        payload += "Sec-WebSocket-Version: 13\r\n\r\n"

        if __debug__:
            logger.debug('Send upgrade request')

        self.downstream.write(payload)

    def upstream_recv(self, data):
        """
            raw data to websocket frame
            Encoding Client -> Server
            mask the data
        """

        try:
            mask = ''.join(random.sample(string.printable, MASK_LEN))
            if self.upgraded:
                add_ws_encapsulation(data, self.downstream, mask)
            else:
                add_ws_encapsulation(data, self.upgraded_buf, mask)

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
                    if __debug__:
                        logger.debug('Short answer (%s)', repr(d))
                    return
                elif not d.startswith('HTTP/'):
                    raise EOFError('Invalid data')
                elif d.startswith('HTTP/') and not d.startswith(UPGRADE_101_SUCCESS):
                    raise EOFError('Invalid response: {}'.format(repr(data.read())))

                d = data.peek()
                if '\r\n\r\n' not in d:
                    if __debug__:
                        logger.debug('Incomplete header')
                    return

                EOFP = d.index('\r\n\r\n')
                data.drain(EOFP + 4)
                if __debug__:
                    logger.debug('Connection upgraded')

                self.upgraded = True

                if self.upgraded_buf:
                    if __debug__:
                        logger.debug('Flush buffer %d', len(self.upgraded_buf))

                    self.upgraded_buf.write_to(self.downstream)

            if __debug__:
                logger.debug('Parse ws messages')

            while data:
                msg_len, self.offset, self.missing_bytes, _ = remove_ws_encapsulation(
                    data, self.upstream, self.decoded, self.offset, self.missing_bytes
                )

                if __debug__:
                    logger.debug(
                        'Parsed: %d, offset: %d, missing: %d, left: %d',
                        msg_len, self.offset, self.missing_bytes, len(data))

                if not msg_len:
                    break

        except Exception, e:
            raise EOFError(str(e))


class PupyWebSocketServer(PupyWebSocketTransport):
    __slots__ = (
        'user_agent', 'path', 'offset', 'upgraded_buf',
        'missing_bytes', 'upgraded', 'decoded', 'mask',
    )

    def __init__(self, *args, **kwargs):
        PupyWebSocketTransport.__init__(self, *args, **kwargs)
        self.upgraded = False
        self.user_agent = kwargs.pop('user-agent')
        self.path = kwargs.pop('path')
        self.mask = True
        self.offset = 0
        self.missing_bytes = 0
        self.decoded = Buffer()
        self.upgraded_buf = Buffer()

        if __debug__:
            logger.debug(
                'WS Server, path=%s, user-agent=%s',
                self.path, self.user_agent)

    def calculate_response_key(self, key):
        GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
        hsh = sha1(key.encode() + GUID.encode())
        response_key = base64.b64encode(hsh.digest()).strip()
        return response_key.decode('ASCII')

    def bad_request(self, msg):
        if __debug__:
            logger.debug(msg)

        self.downstream.write(error_response)
        self.close()

    def upstream_recv(self, data):
        """
            Encoding server -> client messages
            Messsages shouldn't be masked
        """
        try:
            if self.upgraded:
                add_ws_encapsulation(data, self.downstream)
            else:
                add_ws_encapsulation(data, self.upgraded_buf)

        except Exception as e:
            raise EOFError(str(e))

    def downstream_recv(self, data):
        """
            Decoding client -> server messages
            Message should be masked coming from client
        """

        if not self.upgraded:
            if __debug__:
                logger.debug('WS: Wait for upgrade requet')

            d = data.peek()
            # Handle HTTP GET requests, strip websocket keys, verify UA etc
            if not d.startswith('GET '):
                self.bad_request('Invalid HTTP method or data (%s)', repr(d))

            if '\r\n\r\n' not in d:
                if __debug__:
                    logger.debug('Short read, incomplete header')
                return

            _, path, _ = d.split(' ', 2)
            if path != self.path:
                self.bad_request('Path does not match ({} != {})!'.format(path, self.path))
                return

            wskey = None

            key = re.search(r'\n[sS]ec-[wW]eb[sS]ocket-[kK]ey[\s]*:[\s]*(.*)\r\n', d)
            if key:
                wskey = key.group(1)
            else:
                if __debug__:
                    logger.debug('Unable to get WebSocketKey')

            if self.user_agent:
                ua = re.search(r'\n[uU]ser-[aA]gent:[\s]*(.*)\r\n', d)
                if ua:
                    ua = ua.group(1)
                else:
                    self.bad_request('No User-Agent provided')
                    return

                if ua != self.user_agent:
                    self.bad_request(
                        'Bad User-Agent provided. May be counter-intel ({} != {})'.format(
                            ua, self.user_agent))
                    return

            payload = 'HTTP/1.1 101 Switching Protocols\r\n'
            payload += 'Upgrade: websocket\r\n'
            payload += 'Connection: Upgrade\r\n'

            if wskey:
                payload += 'Sec-WebSocket-Accept: %s\r\n' % (self.calculate_response_key(wskey))

            payload += '\r\n'

            data.drain(d.index('\r\n\r\n') + 4)

            if __debug__:
                logger.debug('Flush upgrade response')

            self.downstream.write(payload)

            if self.upgraded_buf:
                if __debug__:
                    logger.debug('Flush buffer %d', len(self.upgraded_buf))

                self.upgraded_buf.write_to(self.downstream)

            self.upgraded = True


        while data:
            msg_len, self.offset, self.missing_bytes, self.mask = remove_ws_encapsulation(
                data, self.upstream, self.decoded,
                self.offset, self.missing_bytes, self.mask)

            if __debug__:
                logger.debug(
                    'Parsed: %d, offset: %d, missing: %d, left: %d',
                    msg_len, self.offset, self.missing_bytes, len(data))

            if not msg_len:
                break
