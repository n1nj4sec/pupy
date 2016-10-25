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
import argparse
import sys
from .PupyErrors import PupyModuleExit
from .PupyCompleter import PupyModCompleter, void_completer, list_completer
import StringIO
import textwrap
import inspect
import logging

class PupyArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        if 'formatter_class' not in kwargs:
            kwargs['formatter_class']=argparse.RawDescriptionHelpFormatter
        if 'description' in kwargs and kwargs['description']:
            kwargs['description']=textwrap.dedent(kwargs['description'])
        argparse.ArgumentParser.__init__(self, *args, **kwargs)
    def exit(self, status=0, message=None):
        if message:
            self._print_message(message, sys.stderr)
        raise PupyModuleExit("exit with status %s"%status)

    def add_argument(self, *args, **kwargs):
        completer_func=None
        if "completer" in kwargs:
            completer_func=kwargs["completer"]
            del kwargs["completer"]
        elif "choices" in kwargs:
            completer_func=list_completer(kwargs["choices"])
        else:
            completer_func=void_completer
        argparse.ArgumentParser.add_argument(self, *args, **kwargs)
        kwargs['completer']=completer_func
        completer=self.get_completer()
        for a in args:
            if a.startswith("-"):
                completer.add_optional_arg(a, **kwargs)
            else:
                completer.add_positional_arg(a, **kwargs)

    def get_completer(self):
        if hasattr(self,'pupy_mod_completer') and self.pupy_mod_completer is not None:
            return self.pupy_mod_completer
        else:
            self.pupy_mod_completer=PupyModCompleter()
            return self.pupy_mod_completer
    #TODO handle completer kw for add_mutually_exclusive_group (ex modules/pyexec.py)

class PupyModule(object):
    """
        This is the class all the pupy scripts must inherit from
        max_clients -> max number of clients the script can be sent at once (0=infinite)
        daemon_script -> script that will continue running in background once started
    """
    max_clients=0 #define on how much clients you module can be run in one command. For example an interactive module should be 1 client max at a time. set to 0 for unlimited
    need_at_least_one_client=True #set to False if your module doesn't need any client connected
    daemon=False #if your module is meant to run in background, set this to True and override the stop_daemon method.
    unique_instance=False # if True, don't start a new module and use another instead
    dependencies=[] #dependencies to push on the remote target. same as calling self.client.load_package
    compatible_systems=[] #should be changed by decorator @config
    category="general" # to sort modules by categories. should be changed by decorator @config
    tags=[] # to add search keywords. should be changed by decorator @config
    is_module=True # if True, module have to be run with "run <module_name", if False it can be called directly without run

    def __init__(self, client, job, formatter=None, stdout=None):
        """ client must be a PupyClient instance """
        self.client=client
        self.job=job
        if formatter is None:
            from .PupyCmd import PupyCmd
            self.formatter=PupyCmd
        else:
            self.formatter=formatter
        if stdout is None:
            self.stdout=StringIO.StringIO()
            self.del_close=True
        else:
            self.stdout=stdout
            self.del_close=False
        self.init_argparse()

    @classmethod
    def get_name(cls):
        """ return module name by looking parents classes """
        #example when using class context managers :
        #(<class 'pupylib.PupyModule.NewClass'>, <class 'pupylib.PupyModule.NewClass'>, <class 'msgbox.MsgBoxPopup'>, <class 'pupylib.PupyModule.PupyModule'>, <type 'object'>)
        for cls in inspect.getmro(cls):
            if cls.__name__!="NewClass":
                return cls.__module__

    def __del__(self):
        if self.del_close:
            self.stdout.close()

    def import_dependencies(self):
        if type(self.dependencies) == dict:
            dependencies = self.dependencies.get('all', []) + \
              self.dependencies.get(self.client.platform, [])
        else:
            dependencies = self.dependencies

        for d in dependencies:
            self.client.load_package(d)

    def init_argparse(self):
        """ Override this class to define your own arguments. """
        self.arg_parser = PupyArgumentParser(prog='PupyModule', description='PupyModule default description')

    def is_compatible(self):
        """ override this method to define if the script is compatible with the givent client. The first value of the returned tuple is True if the module is compatible with the client and the second is a string explaining why in case of incompatibility"""
        if "all" in self.compatible_systems or len(self.compatible_systems)==0:
            return (True,"")
        elif "android" in self.compatible_systems and self.client.is_android():
            return (True,"")
        elif "windows" in self.compatible_systems and self.client.is_windows():
            return (True,"")
        elif "linux" in self.compatible_systems and self.client.is_linux():
            return (True,"")
        elif ("darwin" in self.compatible_systems or "osx" in self.compatible_systems) and self.client.is_darwin():
            return (True,"")
        elif "unix" in self.compatible_systems and self.client.is_unix():
            return (True,"")
        return (False, "This module currently only support the following systems: %s"%(','.join(self.compatible_systems)))

    def is_daemon(self):
        return self.daemon

    def stop_daemon(self):
        """ override this method to define how to stop your module if the module is a deamon or is launch as a job """
        pass

    def run(self, args):
        """
            the parameter args is an object as returned by the parse_args() method from argparse. You can define your arguments options in the init_argparse() method
            The run method does not return any argument. You can raise PupyModuleError in case of error
            NOTICE: DO NOT use print in this function, always use self.rawlog, self.log, self.error and self.warning instead
        """
        raise NotImplementedError("PupyModule's run method has not been implemented !")

    def encode(self, msg):
        if type(msg) == unicode:
            return msg
        else:
            return str(msg).decode('utf8', errors="replace")

    def rawlog(self, msg):
        """ log data to the module stdout """
        self.stdout.write(self.encode(msg))

    def log(self, msg):
        self.stdout.write(self.encode(self.formatter.format_log(msg)))

    def error(self, msg):
        self.stdout.write(self.encode(self.formatter.format_error(msg)))

    def warning(self, msg):
        self.stdout.write(self.encode(self.formatter.format_warning(msg)))

    def success(self, msg):
        self.stdout.write(self.encode(self.formatter.format_success(msg)))

    def info(self, msg):
        self.stdout.write(self.encode(self.formatter.format_info(msg)))


def config(**kwargs):
    for l in ["compat","compatibilities","compatibility","tags"]:
        if l in kwargs:
            if type(kwargs[l])!=list:
                kwargs[l]=[kwargs[l]]

    def class_rebuilder(cls):
        class NewClass(cls):
            __doc__=cls.__doc__
            tags=kwargs.get('tags',cls.tags)
            category=kwargs.get('category', kwargs.get('cat', cls.category))
            compatible_systems=kwargs.get('compatibilities',kwargs.get('compatibility',kwargs.get('compat',cls.compatible_systems)))
            daemon=kwargs.get('daemon', cls.daemon)
            max_clients=kwargs.get('max_clients', cls.max_clients)
        return NewClass
    for k in kwargs.iterkeys():
        if k not in ['tags', 'category', 'cat', 'compatibilities', 'compatibility', 'compat', 'daemon', 'max_clients' ]:
            logging.warning("Unknown argument \"%s\" to @config context manager"%k)
    return class_rebuilder
