"""
SocksiPy - Python SOCKS module.
Version 1.5.7

Copyright 2006 Dan-Haim. All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
3. Neither the name of Dan Haim nor the names of his contributors may be used
   to endorse or promote products derived from this software without specific
   prior written permission.

THIS SOFTWARE IS PROVIDED BY DAN HAIM "AS IS" AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
EVENT SHALL DAN HAIM OR HIS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA
OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMANGE.


This module provides a standard socket-like interface for Python
for tunneling connections through SOCKS proxies.

===============================================================================

Minor modifications made by Christopher Gilbert (http://motomastyle.com/)
for use in PyLoris (http://pyloris.sourceforge.net/)

Minor modifications made by Mario Vilas (http://breakingcode.wordpress.com/)
mainly to merge bug fixes found in Sourceforge

Modifications made by Anorov (https://github.com/Anorov)
-Forked and renamed to PySocks
-Fixed issue with HTTP proxy failure checking (same bug that was in the old ___recvall() method)
-Included SocksiPyHandler (sockshandler.py), to be used as a urllib2 handler,
 courtesy of e000 (https://github.com/e000): https://gist.github.com/869791#file_socksipyhandler.py
-Re-styled code to make it readable
    -Aliased PROXY_TYPE_SOCKS5 -> SOCKS5 etc.
    -Improved exception handling and output
    -Removed irritating use of sequence indexes, replaced with tuple unpacked variables
    -Fixed up Python 3 bytestring handling - chr(0x03).encode() -> b"\x03"
    -Other general fixes
-Added clarification that the HTTP proxy connection method only supports CONNECT-style tunneling HTTP proxies
-Various small bug fixes
"""

__all__ = (
    'PROXY_TYPES',
    'set_default_proxy',
    'get_default_proxy',
    'create_connection',
)

__version__ = "1.5.7"

import struct
from errno import EOPNOTSUPP, EINVAL, EAGAIN
from io import BytesIO
from os import SEEK_CUR
import os
from collections import Callable
from base64 import b64encode

try:
    from http_parser.parser import HttpParser
except ImportError:
    from http_parser.pyparser import HttpParser

from urllib_auth import (
    AuthenticationError, Authentication
)

from .netcreds import find_first_cred

from . import getLogger

if os.name == 'nt':
    try:
        import win_inet_pton
        assert win_inet_pton

        import socket
    except ImportError:
        raise ImportError('To run PySocks under windows you need to install win_inet_pton')
else:
    import socket

logger = getLogger('tinyhttp')

PROXY_TYPE_SOCKS4 = SOCKS4 = 1
PROXY_TYPE_SOCKS5 = SOCKS5 = 2
PROXY_TYPE_HTTP = HTTP = 3

PROXY_TYPES = {"SOCKS4": SOCKS4, "SOCKS5": SOCKS5, "HTTP": HTTP}
PRINTABLE_PROXY_TYPES = dict(zip(PROXY_TYPES.values(), PROXY_TYPES.keys()))

_orgsocket = _orig_socket = socket.socket

class ProxyError(IOError):
    """
    socket_err contains original socket.error exception.
    """

    __slots__ = ('msg', 'socket_err')

    def __init__(self, msg, socket_err=None):
        self.msg = msg
        self.socket_err = socket_err

        if socket_err:
            self.msg += ": {0}".format(socket_err)

    def __str__(self):
        return self.msg


class GeneralProxyError(ProxyError):
    pass


class ProxyConnectionError(ProxyError):
    pass


class SOCKS5AuthError(ProxyError):
    pass


class SOCKS5Error(ProxyError):
    pass


class SOCKS4Error(ProxyError):
    pass


class HTTPError(ProxyError):
    pass


class AuthenticationRequired(ProxyError):
    __slots__ = ('methods',)

    def __init__(self, methods):
        super(AuthenticationRequired, self).__init__(
            'Authentication required, supported methods: {}'.format(
                ';'.join(methods)))
        self.methods = methods


class AuthenticationImpossible(EOFError):
    pass


SOCKS4_ERRORS = {
    0x5B: "Request rejected or failed",
    0x5C: "Request rejected because SOCKS server cannot connect to identd on the client",
    0x5D: "Request rejected because the client program and identd report different user-ids"
}

SOCKS5_ERRORS = {
    0x01: "General SOCKS server failure",
    0x02: "Connection not allowed by ruleset",
    0x03: "Network unreachable",
    0x04: "Host unreachable",
    0x05: "Connection refused",
    0x06: "TTL expired",
    0x07: "Command not supported, or protocol error",
    0x08: "Address type not supported"
}

DEFAULT_PORTS = {
    SOCKS4: 1080,
    SOCKS5: 1080,
    HTTP: 8080
}

def set_default_proxy(proxy_type=None, addr=None, port=None, rdns=True, username=None, password=None):
    """
    set_default_proxy(proxy_type, addr[, port[, rdns[, username, password]]])

    Sets a default proxy which all further socksocket objects will use,
    unless explicitly changed. All parameters are as for socket.set_proxy().
    """
    socksocket.default_proxy = (proxy_type, addr, port, rdns,
                                username.encode() if username else None,
                                password.encode() if password else None)

setdefaultproxy = set_default_proxy

def get_default_proxy():
    """
    Returns the default proxy, set by set_default_proxy.
    """
    return socksocket.default_proxy

getdefaultproxy = get_default_proxy

def wrap_module(module):
    """
    Attempts to replace a module's socket library with a SOCKS socket. Must set
    a default proxy using set_default_proxy(...) first.
    This will only work on modules that import socket directly into the namespace;
    most of the Python Standard Library falls into this category.
    """
    if socksocket.default_proxy:
        module.socket.socket = socksocket
    else:
        raise GeneralProxyError("No default proxy specified")

wrapmodule = wrap_module

def create_connection(dest_pair, proxy_type=None, proxy_addr=None,
                      proxy_port=None, proxy_rdns=True,
                      proxy_username=None, proxy_password=None,
                      timeout=None, source_address=None,
                      socket_options=None):
    """create_connection(dest_pair, *[, timeout], **proxy_args) -> socket object

    Like socket.create_connection(), but connects to proxy
    before returning the socket object.

    dest_pair - 2-tuple of (IP/hostname, port).
    **proxy_args - Same args passed to socksocket.set_proxy() if present.
    timeout - Optional socket timeout value, in seconds.
    source_address - tuple (host, port) for the socket to bind to as its source
    address before connecting (only for compatibility)
    """
    # Remove IPv6 brackets on the remote address and proxy address.
    remote_host, remote_port = dest_pair
    if remote_host.startswith('['):
        remote_host = remote_host.strip('[]')
    if proxy_addr and proxy_addr.startswith('['):
        proxy_addr = proxy_addr.strip('[]')

    err = None

    # Allow the SOCKS proxy to be on IPv4 or IPv6 addresses.
    for r in socket.getaddrinfo(proxy_addr, proxy_port, 0, socket.SOCK_STREAM):
        family, socket_type, proto, canonname, sa = r
        sock = None
        try:
            sock = socksocket(family, socket_type, proto)

            if socket_options:
                for opt in socket_options:
                    sock.setsockopt(*opt)

            if isinstance(timeout, (int, float)):
                sock.settimeout(timeout)

            if proxy_type:
                sock.set_proxy(proxy_type, proxy_addr, proxy_port, proxy_rdns,
                               proxy_username, proxy_password, None)
            if source_address:
                sock.bind(source_address)

            sock.connect((remote_host, remote_port))
            return sock

        except (socket.error, ProxyConnectionError) as e:
            err = e
            if sock:
                sock.close()
                sock = None

    if err:
        raise err

    raise socket.error("gai returned empty list.")

class _BaseSocket(socket.socket):
    """Allows Python 2's "delegated" methods such as send() to be overridden
    """

    def __init__(self, *args, **kwargs):
        _orig_socket.__init__(self, *args, **kwargs)

        self._orig_args = args
        self._orig_kwargs = kwargs
        self._savedmethods = dict()
        for name in self._savenames:
            self._savedmethods[name] = getattr(self, name)
            delattr(self, name)  # Allows normal overriding mechanism to work

    _savenames = list()

def _makemethod(name):
    return lambda self, *pos, **kw: self._savedmethods[name](*pos, **kw)
for name in ("sendto", "send", "recvfrom", "recv"):
    method = getattr(_BaseSocket, name, None)

    # Determine if the method is not defined the usual way
    # as a function in the class.
    # Python 2 uses __slots__, so there are descriptors for each method,
    # but they are not functions.
    if not isinstance(method, Callable):
        _BaseSocket._savenames.append(name)
        setattr(_BaseSocket, name, _makemethod(name))

class socksocket(_BaseSocket):
    """socksocket([family[, type[, proto]]]) -> socket object

    Open a SOCKS enabled socket. The parameters are the same as
    those of the standard socket init. In order for SOCKS to work,
    you must specify family=AF_INET and proto=0.
    The "type" argument must be either SOCK_STREAM or SOCK_DGRAM.
    """

    default_proxy = None

    __slots__ = (
        'proxy', '_proxy_negotiators',
        'proxy_sockname', 'proxy_peername',
        '_socks5_bind_addr', '_proxyconn', '_last_addr'
    )

    def __init__(self, family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0, *args, **kwargs):
        if type not in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            msg = "Socket type must be stream or datagram, not {!r}"
            raise ValueError(msg.format(type))

        _BaseSocket.__init__(self, family, type, proto, *args, **kwargs)
        self._socks5_bind_addr = None
        self._proxyconn = None  # TCP connection to keep UDP relay alive
        self._last_addr = None

        if self.default_proxy:
            self.proxy = [self.default_proxy]
        else:
            self.proxy = []
        self.proxy_sockname = None
        self.proxy_peername = None

    def _readall(self, file, count):
        """
        Receive EXACTLY the number of bytes requested from the file object.
        Blocks until the required number of bytes have been received.
        """
        data = b""
        while len(data) < count:
            d = file.read(count - len(data))
            if not d:
                raise GeneralProxyError("Connection closed unexpectedly")
            data += d
        return data

    def add_proxy(
        self, proxy_type=None, addr=None, port=None,
            rdns=True, username=None, password=None, auth_type=None):
        """set_proxy(proxy_type, addr[, port[, rdns[, username[, password]]]])
        Sets the proxy to be used.

        proxy_type -    The type of the proxy to be used. Three types
                        are supported: PROXY_TYPE_SOCKS4 (including socks4a),
                        PROXY_TYPE_SOCKS5 and PROXY_TYPE_HTTP
        addr -        The address of the server (IP or DNS).
        port -        The port of the server. Defaults to 1080 for SOCKS
                       servers and 8080 for HTTP proxy servers.
        rdns -        Should DNS queries be performed on the remote side
                       (rather than the local side). The default is True.
                       Note: This has no effect with SOCKS4 servers.
        username -    Username to authenticate with to the server.
                       The default is no authentication.
        password -    Password to authenticate with to the server.
                       Only relevant when username is also provided.
        auth_type -   Engine to perform authentication (None = BASIC, 'NTLM' = NTLM)
        """

        if type(proxy_type) in (str, unicode):
            proxy_type = PROXY_TYPES.get(proxy_type)
            if not proxy_type:
                raise ValueError('Unknown proxy type {}'.format(proxy_type))

        self.proxy.append([
            proxy_type, addr, port, rdns,
            username.encode() if username else None,
            password.encode() if password else None,
            auth_type])

    def set_proxy(self, *args, **kwargs):
        self.reset_proxies()
        self.add_proxy(*args, **kwargs)

    def reset_proxies(self):
        self.proxy = []

    setproxy = set_proxy

    def listen(self, cnt=0):
        if not self.proxy:
            return _orig_socket.listen(self, cnt)

        if self.proxy[-1][0] != SOCKS5:
            raise socket.error(EINVAL, 'Only SOCKS5 proxies supported')

        if not self._socks5_bind_addr:
            raise socket.error(EINVAL, 'Socket was not bound')

        return

    def accept(self):
        if not self.proxy:
            return _orig_socket.accept(self)

        if self.proxy[-1][0] != SOCKS5:
            raise socket.error(EINVAL, 'Only SOCKS5 proxies supported')

        if not self._socks5_bind_addr:
            raise socket.error(EINVAL, 'Socket was not bound')

        return self._accept()

    def bind(self, *pos, **kw):
        """
        Implements proxy connection for UDP sockets,
        which happens during the bind() phase.
        """

        if not self.proxy:
            return _orig_socket.bind(self, *pos, **kw)

        if self.proxy[-1][0] != SOCKS5:
            raise socket.error(EINVAL, 'Only SOCKS5 proxies supported')

        if self.type != socket.SOCK_DGRAM:
            bind_addr = pos[0]
            if type(bind_addr) is not tuple or len(bind_addr) != 2:
                raise socket.error(EINVAL, 'Bind address should be tuple')

            self._socks5_bind_addr = bind_addr
            self.close()
            return True

        if self._proxyconn:
            raise socket.error(EINVAL, "Socket already bound to an address")

        last_proxy = self.proxy[-1]
        last_proxy_type = last_proxy[0]

        if last_proxy_type != SOCKS5:
            msg = "UDP only supported by SOCKS5 proxy type"
            raise socket.error(EOPNOTSUPP, msg)

        _BaseSocket.bind(self, *pos, **kw)

        # Need to specify actual local port because
        # some relays drop packets if a port of zero is specified.
        # Avoid specifying host address in case of NAT though.
        _, port = self.getsockname()
        dst = ("0", port)

        while True:
            try:
                self._proxyconn = _orig_socket()
                self._connect_first(self._proxyconn)
                self._connect_rest(self._proxyconn)
                break

            except AuthenticationRequired:
                _orig_socket.__init__(
                    self, *self._orig_args, **self._orig_kwargs)

        proxy = self.proxy[-1]

        properties = proxy[3:]

        UDP_ASSOCIATE = b"\x03"
        _, relay = self._SOCKS5_request(self._proxyconn, UDP_ASSOCIATE, dst, properties)

        # The relay is most likely on the same host as the SOCKS proxy,
        # but some proxies return a private IP address (10.x.y.z)
        _, port = relay

        if len(self.proxy) == 1:
            proxy_host, proxy_port = self._proxy_addr(proxy)
            _BaseSocket.connect(self, (proxy_host, port))
        else:
            self._connect_first()
            self._connect_rest()

        self.proxy_sockname = ("0.0.0.0", 0)  # Unknown

    def sendto(self, bytes, *args, **kwargs):
        if self.type != socket.SOCK_DGRAM:
            return _BaseSocket.sendto(self, bytes, *args, **kwargs)
        if not self._proxyconn:
            self.bind(("", 0))

        address = args[-1]
        flags = args[:-1]

        header = BytesIO()
        RSV = b"\x00\x00"
        header.write(RSV)
        STANDALONE = b"\x00"
        header.write(STANDALONE)
        self._write_SOCKS5_address(address, header, self.proxy[-1][3:])

        sent = _BaseSocket.send(self, header.getvalue() + bytes, *flags, **kwargs)
        return sent - header.tell()

    def send(self, bytes, flags=0, **kwargs):
        if self.type == socket.SOCK_DGRAM:
            return self.sendto(bytes, flags, self.proxy_peername, **kwargs)
        else:
            return _BaseSocket.send(self, bytes, flags, **kwargs)

    def recvfrom(self, bufsize, flags=0):
        if self.type != socket.SOCK_DGRAM:
            return _BaseSocket.recvfrom(self, bufsize, flags)
        if not self._proxyconn:
            self.bind(("", 0))

        buf = BytesIO(_BaseSocket.recv(self, bufsize, flags))
        buf.seek(+2, SEEK_CUR)
        frag = buf.read(1)
        if ord(frag):
            raise NotImplementedError("Received UDP packet fragment")
        fromhost, fromport = self._read_SOCKS5_address(buf)

        if self.proxy_peername:
            peerhost, peerport = self.proxy_peername
            if fromhost != peerhost or peerport not in (0, fromport):
                raise socket.error(EAGAIN, "Packet filtered")

        return (buf.read(), (fromhost, fromport))

    def recv(self, *pos, **kw):
        bytes, _ = self.recvfrom(*pos, **kw)
        return bytes

    def recv_http_response(self, conn):
        response = HttpParser(kind=1)
        status_code = None
        headers = None

        try:
            while True:
                chunk = conn.recv(1024)

                response.execute(chunk, len(chunk))
                if response.is_headers_complete():
                    headers = response.get_headers()
                    status_code = response.get_status_code()

                    content_length = headers.get('content-length')
                    if not content_length or int(content_length) == 0:
                        break

                if response.is_message_complete():
                    break

                if not chunk:
                    raise EOFError('Incomplete Message')

        except Exception as e:
            raise GeneralProxyError(
                'HTTP Proxy communication error ({})'.format(e))

        return status_code, headers

    def close(self):
        if self._proxyconn:
            self._proxyconn.close()
        return _BaseSocket.close(self)

    def get_proxy_sockname(self):
        """
        Returns the bound IP address and port number at the proxy.
        """
        return self.proxy_sockname

    getproxysockname = get_proxy_sockname

    def get_proxy_peername(self):
        """
        Returns the IP and port number of the proxy.
        """
        return _BaseSocket.getpeername(self)

    getproxypeername = get_proxy_peername

    def get_peername(self):
        """
        Returns the IP address and port number of the destination
        machine (note: get_proxy_peername returns the proxy)
        """
        return self.proxy_peername

    getpeername = get_peername

    def _negotiate_SOCKS5(self, conn, dest_addr, properties):
        """
        Negotiates a stream connection through a SOCKS5 server.
        """
        CONNECT = b"\x01"
        self.proxy_peername, self.proxy_sockname = self._SOCKS5_request(
            conn, CONNECT, dest_addr, properties)

    def _SOCKS5_request(self, conn, cmd, dst, properties):
        """
        Send SOCKS5 request with given command (CMD field) and
        address (DST field). Returns resolved DST address that was used.
        """
        rdns, username, password, _ = properties

        writer = conn.makefile("wb")
        reader = conn.makefile("rb", 0)  # buffering=0 renamed in Python 3
        try:
            # First we'll send the authentication packages we support.
            if username and password:
                # The username/password details were supplied to the
                # set_proxy method so we support the USERNAME/PASSWORD
                # authentication (in addition to the standard none).
                writer.write(b"\x05\x02\x00\x02")
            else:
                # No username/password were entered, therefore we
                # only support connections with no authentication.
                writer.write(b"\x05\x01\x00")

            # We'll receive the server's response to determine which
            # method was selected
            writer.flush()
            chosen_auth = self._readall(reader, 2)

            if chosen_auth[0:1] != b"\x05":
                # Note: string[i:i+1] is used because indexing of a bytestring
                # via bytestring[i] yields an integer in Python 3
                raise GeneralProxyError("SOCKS5 proxy server sent invalid data")

            # Check the chosen authentication method

            if chosen_auth[1:2] == b"\x02":
                # Okay, we need to perform a basic username/password
                # authentication.
                writer.write(
                    b"\x01" + chr(len(username)).encode() + \
                    username + chr(len(password)).encode() + password)
                writer.flush()
                auth_status = self._readall(reader, 2)
                if auth_status[0:1] != b"\x01":
                    # Bad response
                    raise GeneralProxyError("SOCKS5 proxy server sent invalid data")
                if auth_status[1:2] != b"\x00":
                    # Authentication failed
                    raise SOCKS5AuthError("SOCKS5 authentication failed")

                # Otherwise, authentication succeeded

            # No authentication is required if 0x00
            elif chosen_auth[1:2] != b"\x00":
                # Reaching here is always bad
                if chosen_auth[1:2] == b"\xFF":
                    raise SOCKS5AuthError("All offered SOCKS5 authentication methods were rejected")
                else:
                    raise GeneralProxyError("SOCKS5 proxy server sent invalid data")

            # Now we can request the actual connection
            writer.write(b"\x05" + cmd + b"\x00")
            resolved = self._write_SOCKS5_address(conn, dst, writer, properties)
            writer.flush()

            # Get the response
            resp = self._readall(reader, 3)
            if resp[0:1] != b"\x05":
                raise GeneralProxyError("SOCKS5 proxy server sent invalid data")

            status = ord(resp[1:2])
            if status != 0x00:
                # Connection failed: server returned an error
                error = SOCKS5_ERRORS.get(status, "Unknown error")
                raise SOCKS5Error("{0:#04x}: {1}".format(status, error))

            # Get the bound address/port
            bnd = self._read_SOCKS5_address(reader)
            return (resolved, bnd)
        finally:
            reader.close()
            writer.close()

    def _write_SOCKS5_address(self, conn, addr, file, properties):
        """
        Return the host and port packed for the SOCKS5 protocol,
        and the resolved address as a tuple object.
        """
        host, port = addr
        rdns, username, password, _ = properties
        family_to_byte = {socket.AF_INET: b"\x01", socket.AF_INET6: b"\x04"}

        # If the given destination address is an IP address, we'll
        # use the IP address request even if remote resolving was specified.
        # Detect whether the address is IPv4/6 directly.
        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                addr_bytes = socket.inet_pton(family, host)
                file.write(family_to_byte[family] + addr_bytes)
                host = socket.inet_ntop(family, addr_bytes)
                file.write(struct.pack(">H", port))
                return host, port
            except socket.error:
                continue

        # Well it's not an IP number, so it's probably a DNS name.
        if rdns:
            # Resolve remotely
            try:
                host_bytes = host.encode('idna')
            except:
                host_bytes = host

            file.write(b"\x03" + chr(len(host_bytes)).encode() + host_bytes)
        else:
            # Resolve locally
            addresses = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM, socket.IPPROTO_TCP, socket.AI_ADDRCONFIG)
            # We can't really work out what IP is reachable, so just pick the
            # first.
            target_addr = addresses[0]
            family = target_addr[0]
            host = target_addr[4][0]

            addr_bytes = socket.inet_pton(family, host)
            file.write(family_to_byte[family] + addr_bytes)
            host = socket.inet_ntop(family, addr_bytes)
        file.write(struct.pack(">H", port))
        return host, port

    def _read_SOCKS5_address(self, file):
        atyp = self._readall(file, 1)
        if atyp == b"\x01":
            addr = socket.inet_ntoa(self._readall(file, 4))
        elif atyp == b"\x03":
            length = self._readall(file, 1)
            addr = self._readall(file, ord(length))
        elif atyp == b"\x04":
            addr = socket.inet_ntop(socket.AF_INET6, self._readall(file, 16))
        else:
            raise GeneralProxyError("SOCKS5 proxy server sent invalid data")

        port = struct.unpack(">H", self._readall(file, 2))[0]
        return addr, port

    def _negotiate_SOCKS4(self, conn, dest, properties):
        """
        Negotiates a connection through a SOCKS4 server.
        """
        dest_addr, dest_port = dest
        rdns, username, password, _ = properties

        writer = conn.makefile("wb")
        reader = conn.makefile("rb", 0)  # buffering=0 renamed in Python 3
        try:
            # Check if the destination address provided is an IP address
            remote_resolve = False
            try:
                addr_bytes = socket.inet_aton(dest_addr)
            except socket.error:
                # It's a DNS name. Check where it should be resolved.
                if rdns:
                    addr_bytes = b"\x00\x00\x00\x01"
                    remote_resolve = True
                else:
                    addr_bytes = socket.inet_aton(socket.gethostbyname(dest_addr))

            # Construct the request packet
            writer.write(struct.pack(">BBH", 0x04, 0x01, dest_port))
            writer.write(addr_bytes)

            # The username parameter is considered userid for SOCKS4
            if username:
                writer.write(username)
            writer.write(b"\x00")

            # DNS name if remote resolving is required
            # NOTE: This is actually an extension to the SOCKS4 protocol
            # called SOCKS4A and may not be supported in all cases.
            if remote_resolve:
                try:
                    dest_addr = dest_addr.encode('idna')
                except:
                    pass

                writer.write(dest_addr + b"\x00")
            writer.flush()

            # Get the response from the server
            resp = self._readall(reader, 8)
            if resp[0:1] != b"\x00":
                # Bad data
                raise GeneralProxyError("SOCKS4 proxy server sent invalid data")

            status = ord(resp[1:2])
            if status != 0x5A:
                # Connection failed: server returned an error
                error = SOCKS4_ERRORS.get(status, "Unknown error")
                raise SOCKS4Error("{0:#04x}: {1}".format(status, error))

            # Get the bound address/port
            self.proxy_sockname = (socket.inet_ntoa(resp[4:]), struct.unpack(">H", resp[2:4])[0])
            if remote_resolve:
                self.proxy_peername = socket.inet_ntoa(addr_bytes), dest_port
            else:
                self.proxy_peername = dest_addr, dest_port
        finally:
            reader.close()
            writer.close()

    def _negotiate_HTTP(self, conn, dest, properties):
        """
        Negotiates a connection through an HTTP server.
        NOTE: This currently only supports HTTP CONNECT-style proxies.
        """

        dest_addr, dest_port = dest
        rdns, username, password, auth_type = properties

        # If we need to resolve locally, we do this now
        addr = dest_addr if rdns else socket.gethostbyname(dest_addr)
        try:
            addr = addr.encode('idna')
        except:
            pass

        try:
            dest_addr = dest_addr.encode('idna')
        except:
            pass

        http_headers = [
            b"CONNECT " + addr + b":" + str(dest_port).encode() + b" HTTP/1.1",
            b"Host: " + dest_addr,
            b"Connection: Keep-Alive",
            b"Proxy-Connection: keep-alive",
        ]

        if auth_type:
            if not (username and password):
                curr_addr, curr_port = self._last_addr
                cred = find_first_cred('http', curr_addr, curr_port)
                if cred:
                    username = cred.user
                    password = cred.password

            if 'BASIC' in auth_type:
                if not (username and password):
                    raise AuthenticationImpossible(
                        'Authentication required, but credentials are not provided')

                http_headers.append(b"Proxy-Authorization: basic " + b64encode(username + b":" + password))

            elif 'NTLM' in auth_type or 'NEGOTIATE' in auth_type:
                ctx = Authentication(logger)

                domain = None
                if username and '\\' in username:
                    domain, username = username.split('\\', 1)

                try:
                    _, method, payload = ctx.create_auth1_message(
                        domain, username, password,
                        'http://{}:{}'.format(dest_addr, dest_port), auth_type
                    )

                except AuthenticationError as e:
                    raise AuthenticationImpossible('Error during SSP authentication: {}'.format(e))

                ntlm_headers = list(http_headers)
                ntlm_headers.append(b'Proxy-Authorization: ' + ' '.join([method, payload]))
                ntlm_headers.append(b'\r\n')
                ntlm_payload = b'\r\n'.join(ntlm_headers)

                conn.sendall(ntlm_payload)

                status_code, headers = self.recv_http_response(conn)

                if status_code != 407:
                    raise GeneralProxyError(
                        'Invalid Authentication Sequence (STATUS: {})'.format(
                            status_code))

                challenge = None

                for header, value in headers.iteritems():
                    if header.lower() == 'proxy-authenticate':
                        value = value.strip()
                        if not value.startswith(method + ' '):
                            raise GeneralProxyError(
                                'Invalid Authentication Sequence (Invalid payload)')

                        _, challenge = value.split(' ', 1)

                if not challenge:
                    raise GeneralProxyError(
                        'Invalid Authentication Sequence (Challenge not found)')

                try:
                    _, method, payload = ctx.create_auth2_message(challenge)
                except AuthenticationError as e:
                    raise AuthenticationImpossible(
                        'Error during SSP authentication (Step 2): {}'.format(e))

                http_headers.append('Proxy-Authorization: ' + ' '.join([method, payload]))

            else:
                raise GeneralProxyError('Unsupported authentication scheme: {}'.format(auth_type))

        http_headers.append(b'\r\n')
        request = b'\r\n'.join(http_headers)

        conn.sendall(request)

        status_code, headers = self.recv_http_response(conn)

        if status_code in (401, 407):
            if auth_type is not None:
                raise AuthenticationImpossible(
                    'Authentication using method {} has been failed'.format(auth_type))

            if not username and password:
                raise AuthenticationImpossible('Authentication required, but credentials are not provided')

            methods = headers.get('Proxy-Authenticate')
            if not methods:
                methods = ['BASIC']
            else:
                methods = [x.strip().upper() for x in methods.split(',')]

            raise AuthenticationRequired(methods)

        elif status_code != 200:
            error = "ERROR: {0}".format(status_code)
            if status_code in (400, 403, 405):
                # It's likely that the HTTP proxy server does not support the CONNECT tunneling method
                error += ("\n[*] Note: The HTTP proxy server may not be supported by PySocks"
                          " (must be a CONNECT tunnel proxy)")
            raise HTTPError(error)

        self.proxy_sockname = (b"0.0.0.0", 0)
        self.proxy_peername = addr, dest_port

    _proxy_negotiators = {
        SOCKS4: _negotiate_SOCKS4,
        SOCKS5: _negotiate_SOCKS5,
        HTTP: _negotiate_HTTP
    }

    def _connect_first(self, conn=None, port=None):
        proxy = self.proxy[0]
        proxy_type = proxy[0]

        proxy_host, proxy_port = self._proxy_addr(proxy)
        if conn is None:
            conn = self

        if port is not None and len(self.proxy) == 1:
            proxy_port = port

        try:
            if conn is self:
                _BaseSocket.connect(self, (proxy_host, proxy_port))
            else:
                conn.connect((proxy_host, proxy_port))

            self._setkeepalive(conn)
            self._last_addr = proxy_host, proxy_port

        except socket.error as e:
            conn.close()

            proxy_server = '{}:{}'.format(proxy_host, proxy_port)
            printable_type = PRINTABLE_PROXY_TYPES[proxy_type]

            msg = 'Error connecting to {} proxy {}: {}'.format(
                printable_type, proxy_server, e)

            raise ProxyConnectionError(msg, e)

    def _connect_rest(self, conn=None, last=None, port=None):
        if conn is None:
            conn = self

        proxy = self.proxy[0]
        previous_proxy_type = proxy[0]
        previous_proxy_properties = proxy[3:]

        proxies = self.proxy[1:last]

        rest = len(proxies)

        for i, proxy in enumerate(proxies):
            next_proxy_addr = self._proxy_addr(proxy)
            try:
                # Calls negotiate_{SOCKS4, SOCKS5, HTTP}
                negotiate = self._proxy_negotiators[previous_proxy_type]

                if i == rest-1 and port is not None:
                    next_proxy_addr = (next_proxy_addr[0], port)

                negotiate(self, conn, next_proxy_addr, previous_proxy_properties)
                self._last_addr = next_proxy_addr

                previous_proxy_type = proxy[0]
                previous_proxy_properties = proxy[3:]

            except AuthenticationRequired as error:
                # Mark current proxy as one required authentication
                proxies[i][6] = error.methods
                conn.close()
                raise

            except socket.error as error:
                # Wrap socket errors
                conn.close()
                raise GeneralProxyError("Socket error", error)

            except ProxyError:
                # Protocol error while negotiating with proxy
                conn.close()
                raise

    def _connect(self, conn, dest_addr):
        self._connect_first(conn)
        self._connect_rest(conn)

        proxy = self.proxy[-1]

        previous_proxy_type = proxy[0]
        previous_proxy_properties = proxy[3:]

        try:
            # Calls negotiate_{SOCKS4, SOCKS5, HTTP}
            negotiate = self._proxy_negotiators[previous_proxy_type]
            negotiate(self, conn, dest_addr, previous_proxy_properties)
            self._last_addr = dest_addr

        except AuthenticationRequired as error:
            self.proxy[-1][6] = error.methods
            conn.close()
            raise

        except socket.error as error:
            # Wrap socket errors
            conn.close()
            raise GeneralProxyError("Socket error", error)

        except ProxyError:
            # Protocol error while negotiating with proxy
            conn.close()
            raise

        return True

    def _bind(self, conn, dest_addr):
        self._connect_first(conn)
        self._connect_rest(conn)

        proxy = self.proxy[-1]

        previous_proxy_type = proxy[0]
        previous_proxy_properties = proxy[3:]

        if previous_proxy_type != SOCKS5:
            raise GeneralProxyError('Bind is not supported for non-SOCKS5 proxies')


        SOCKS5_BIND = b'\x02'

        try:
            _, relay = self._SOCKS5_request(
                conn, SOCKS5_BIND, dest_addr, previous_proxy_properties)
        except socket.error as error:
            # Wrap socket errors
            conn.close()
            raise GeneralProxyError("Socket error", error)
        except ProxyError:
            # Protocol error while negotiating with proxy
            conn.close()
            raise

        self.proxy_sockname = relay
        return conn, relay

    def _accept(self):
        conn = _orig_socket()
        relay = None

        while True:
            try:
                _, relay = self._bind(conn, self._socks5_bind_addr)
                break
            except AuthenticationRequired:
                _orig_socket.__init__(
                    self, *self._orig_args, **self._orig_kwargs)

        _, port = relay

        reader = conn.makefile('rb', 0)
        reader.read(3)

        return conn, self._read_SOCKS5_address(reader)

    def connect(self, dest_pair):
        """
        Connects to the specified destination through a proxy.
        Uses the same API as socket's connect().
        To select the proxy server, use set_proxy().

        dest_pair - 2-tuple of (IP/hostname, port).
        """

        if not self.proxy:
            # Treat like regular socket object
            self.proxy_peername = dest_pair
            _BaseSocket.connect(self, *dest_pair)
            self._setkeepalive()
            return

        if len(dest_pair) != 2 or dest_pair[0].startswith("["):
            # Probably IPv6, not supported -- raise an error, and hope
            # Happy Eyeballs (RFC6555) makes sure at least the IPv4
            # connection works...
            raise socket.error("PySocks doesn't support IPv6")

        dest_addr, dest_port = dest_pair

        if self.type == socket.SOCK_DGRAM:
            if not self._proxyconn:
                self.bind(("", 0))
            dest_addr = socket.gethostbyname(dest_addr)

            # If the host address is INADDR_ANY or similar, reset the peer
            # address so that packets are received from any peer
            if dest_addr == "0.0.0.0" and not dest_port:
                self.proxy_peername = None
            else:
                self.proxy_peername = (dest_addr, dest_port)
            return

        # Do a minimal input check first
        if (not isinstance(dest_pair, (list, tuple)) or \
                len(dest_pair) != 2 or \
                not dest_addr or \
                not isinstance(dest_port, int)):
            raise GeneralProxyError("Invalid destination-connection (host, port) pair")

        while True:
            try:
                self._connect(self, dest_pair)
                break
            except AuthenticationRequired:
                _orig_socket.__init__(
                    self, *self._orig_args, **self._orig_kwargs)

    def _proxy_addr(self, proxy):
        """
        Return proxy address to connect to as tuple object
        """
        proxy_type, proxy_addr, proxy_port, _, _, _, _ = proxy
        proxy_port = proxy_port or DEFAULT_PORTS.get(proxy_type)
        if not proxy_port:
            raise GeneralProxyError("Invalid proxy type")
        return proxy_addr, proxy_port

    def _setkeepalive(self, conn=None):
        if conn is None:
            conn = self

        conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        if hasattr(socket, 'TCP_KEEPIDLE') and hasattr(socket, 'TCP_KEEPINTVL') and hasattr(socket, 'TCP_KEEPCNT'):
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 1 * 60)
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 5 * 60)
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 10)
        elif hasattr(socket, 'SIO_KEEPALIVE_VALS') and hasattr(conn, 'ioctl'):
            conn.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 1*60*1000, 5*60*1000))
