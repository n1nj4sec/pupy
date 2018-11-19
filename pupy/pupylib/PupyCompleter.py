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

import os
import os.path
import stat

from argparse import REMAINDER

from .PupyErrors import PupyModuleExit, PupyModuleUsageError
from .payloads.dependencies import paths

def package_completer(module, args, text, context):
    clients = context.server.get_clients(context.handler.default_filter)

    paths_to_scan = set()
    completions = set()

    for client in clients:
        for path in paths(client.platform, client.arch, client.is_posix()):
            paths_to_scan.add(path)

    module_path = text.split('.')

    path_to_scan = os.path.sep.join(module_path)
    for path in paths_to_scan:
        full_path_to_scan = os.path.sep.join([path, path_to_scan])
        dir_to_scan = os.path.dirname(full_path_to_scan)
        if not os.path.isdir(dir_to_scan):
            continue

        for item in os.listdir(dir_to_scan):
            try:
                item_info = os.stat(os.path.join(dir_to_scan, item))
            except OSError:
                continue

            completion = ''
            if stat.S_ISDIR(item_info.st_mode) and os.path.isfile(
                    os.path.join(os.path.join(dir_to_scan, item, '__init__.py'))):
                completion = item
            elif stat.S_ISREG(item_info.st_mode) and item.endswith('.py'):
                completion = os.path.splitext(item)[0]

            completion = '.'.join(module_path[:-1] + [completion])
            if completion.startswith(text) and not item.startswith('__init__.py'):
                completions.add(completion)

    return list(completions)

def commands_completer(module, args, text, context):
    aliases = dict(context.config.items('aliases'))
    modules = list(context.server.iter_modules(
        by_clients=True,
        clients_filter=context.handler.default_filter))
    commands = context.commands.list(False)

    return [
        x+' ' for x in aliases.iterkeys() if x.startswith(text)
    ] + [
        x+' ' for x,_ in commands if x.startswith(text)
    ] + [
        x.get_name()+' ' for x in modules if x.get_name().startswith(text)
    ]

def list_completer(l):
    def func(module, args, text, context):
        return [x+" " for x in l if x.startswith(text)]
    return func

def void_completer(module, args, text, context):
    return []

def remote_path_completer(module, args, text, context, dirs=None):
    results = []
    try:
        import logging
        clients = context.server.get_clients(context.handler.default_filter)
        if len(clients) != 1:
            return []

        path = text or ''

        client = clients[0]
        client.load_package(['pupyutils.basic_cmds', 'scandir'])
        complete = client.remote('pupyutils.basic_cmds', 'complete')
        path, results = complete(path, dirs=dirs)
        if path is not None:
            results = [
                (
                    '/'.join([path, result]) if result else path
                ) for result in results
            ]

    except Exception, e:
        logging.exception("rpc: %s", e)

    return results

def remote_dirs_completer(module, args, text, context):
    return remote_path_completer(module, args, text, context, dirs=True)

def remote_files_completer(module, args, text, context):
    return remote_path_completer(module, args, text, context, dirs=False)

def path_completer(module, args, text, context):
    completions=[]

    if not text:
        completions=os.listdir('.')
    else:
        try:
            dirname=os.path.dirname(text)
            if not dirname:
                dirname="."
            basename=os.path.basename(text)
            for f in os.listdir(dirname):
                if f.startswith(basename):
                    if os.path.isdir(os.path.join(dirname,f)):
                        completions.append(os.path.join(dirname,f)+os.sep)
                    else:
                        completions.append(os.path.join(dirname,f)+" ")
        except:
            pass

    return completions

def module_name_completer(module, args, text, context):

    del module

    modules = (
        x.get_name() for x in context.server.iter_modules(
        by_clients=True,
        clients_filter=context.handler.default_filter)
    )

    return [
        module for module in modules if module.startswith(text) or not(text)
    ]

def module_args_completer(module, args, text, context):
    try:
        args = module.arguments
        module = context.server.get_module(module.module)
    except ValueError:
        return []

    completer = module.arg_parser.get_completer()

    text = text

    return completer.complete(module, args, text, context)


class CompletionContext(object):

    __slots__ = (
        'server', 'handler', 'config', 'commands'
    )

    def __init__(self, server, handler, config, commands):
        self.server = server
        self.handler = handler
        self.config = config
        self.commands = commands

class PupyModCompleter(object):
    def __init__(self, parser):
        self.conf = {
            'positional_args': [],
            'optional_args': [],
        }

        self.parser = parser

    def add_positional_arg(self, names, **kwargs):
        """ names can be a string or a list to pass args aliases at once """
        if not type(names) is list and not type(names) is tuple:
            names = [names]

        for name in names:
            self.conf['positional_args'].append((name, kwargs))

    def add_optional_arg(self, names, **kwargs):
        """ names can be a string or a list to pass args aliases at once """
        if not type(names) is list and not type(names) is tuple:
            names = [names]

        for name in names:
            self.conf['optional_args'].append((name, kwargs))

    def get_optional_nargs(self, name):
        for n, kwargs in self.conf['optional_args']:
            if name == n:
                if 'action' in kwargs:
                    action = kwargs['action']
                    if action in ('store_true', 'store_false'):
                        return 0
                break

        return 1

    def get_optional_args(self, nargs=None):
        if nargs is None:
            return [
                x[0] for x in self.conf['optional_args']
            ]
        else:
            return [
                x[0] for x in self.conf['optional_args'] \
                if self.get_optional_nargs(x[0]) == nargs
            ]

    def get_positional_args(self):
        return self.conf['positional_args']

    def get_positional_arg_index(self, text, tab, context):
        posmax = len(self.get_positional_args())

        if not tab:
            return 0, False

        elif not self.get_positional_args():
            return 0, False

        elif posmax < 2:
            return 0, False

        opt0 = self.get_optional_args(nargs=0)
        opt1 = self.get_optional_args(nargs=1)
        ltab = len(tab)

        i = 0
        omit = 0

        for i in xrange(0, ltab):
            if i >= omit:
                if i-omit >= posmax:
                    return posmax, True

                name, kwargs = self.get_positional_args()[i-omit]
                if 'nargs' in kwargs and kwargs['nargs'] == REMAINDER:
                    return i - omit, True

            if tab[i] in opt0 or (i == ltab-1 and any(opt.startswith(tab[i]) for opt in opt0)):
                omit += 1

            elif tab[i] in opt1 or (i == ltab-1 and any(opt.startswith(tab[i]) for opt in opt1)):
                omit += 1

            elif i > 1 and tab[i-1] in opt1:
                omit += 1

        if not text:
            i += 1

        if i < omit:
            return 0, False

        pos = i - omit
        remainder = False

        name, kwargs = self.get_positional_args()[pos]
        if 'nargs' in kwargs and kwargs['nargs'] == REMAINDER:
            remainder = True

        return pos, remainder

    def get_optional_args_completer(self, name):
        return [
            x[1]["completer"] for x in self.conf["optional_args"] if x[0]==name
        ][0]

    def get_positional_args_completer(self, index):
        if index < len(self.get_positional_args()):
            return self.get_positional_args()[index][1]['completer']

    def complete(self, module, args, text, context):
        if text in self.get_optional_args(nargs=1):
            completer = self.get_optional_args_completer(text)
            return completer(module, args, text, context)

        positional_index, remainder = self.get_positional_arg_index(
            text, args, context)

        if text.startswith('-') and not remainder:
            return [
                x+' ' for x in self.get_optional_args() if x.startswith(text)
            ]
        else:
            completer = self.get_positional_args_completer(positional_index)
            if not completer:
                return None

            if args:
                try:
                    module, args = self.parser.parse_known_args(args)
                except (PupyModuleUsageError, PupyModuleExit):
                    pass

            return completer(module, args, text, context)
