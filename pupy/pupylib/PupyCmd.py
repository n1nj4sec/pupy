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
import sys
import readline
import cmd
import shlex
import string
import re
import os
import os.path
import traceback
import platform
import random
try:
    import __builtin__ as builtins
except ImportError:
    import builtins
from multiprocessing.pool import ThreadPool
import time
import logging
import traceback
import rpyc
import rpyc.utils.classic
from .PupyErrors import PupyModuleExit, PupyModuleError
from .PupyModule import PupyArgumentParser
from .PupyModule import (
    REQUIRE_NOTHING, REQUIRE_STREAM, REQUIRE_REPL, REQUIRE_TERMINAL
)
from .PupyJob import PupyJob
from .PupyCompleter import PupyCompleter
from .PupyVersion import BANNER, BANNER_INFO
from .PupyOutput import *
from argparse import REMAINDER
import copy
from functools import partial
from threading import Event
from pupylib.utils.term import colorize, hint_to_text, obj2utf8, color
from pupylib.utils.network import *

from StringIO import StringIO

from commands import Commands

import pupygen

class ObjectStream(object):
    def __init__(self, display=None):
        self._buffer = []
        self._display = display

    def write(self, data):
        if self._display:
            self._display(data)
        else:
            self._buffer.append(data)

    def close(self):
        pass

    def flush(self):
        pass

    def getvalue(self):
        return self._buffer

class PupyCmd(cmd.Cmd):
    def __init__(self, pupsrv):
        cmd.Cmd.__init__(self)
        self.pupsrv = pupsrv
        self.dnscnc = pupsrv.dnscnc
        self.pupsrv.register_handler(self)
        self.config = pupsrv.config

        self.input = sys.stdin
        self.output = sys.stdout

        self.commands = Commands()

        self.init_readline()
        global color

        self._intro = [
            color(BANNER, 'green'),
            color(BANNER_INFO, 'darkgrey')
        ]

        self.raw_prompt= color('>> ','blue')
        self.prompt = color('>> ','blue', prompt=True)
        self.doc_header = 'Available commands :\n'
        self.default_filter=None
        try:
            if not self.config.getboolean("cmdline","display_banner"):
                self._intro = []
        except Exception:
            pass
        self.aliases={}
        for m in self.pupsrv.get_aliased_modules():
            self.aliases[m]=m
        try:
            for command, alias in self.config.items("aliases"):
                logging.debug("adding alias: %s => %s"%(command, alias))
                self.aliases[command]=alias
        except Exception as e:
            logging.warning("error while parsing aliases from pupy.conf ! %s"%str(traceback.format_exc()))
        self.pupy_completer=PupyCompleter(self.aliases, self.pupsrv)

    @property
    def intro(self):
        return '\n'.join(
            hint_to_text(x) for x in self._intro
        )

    def add_motd(self, motd={}):
        for ok in motd.get('ok', []):
            self._intro.append(ServiceInfo(ok + '\n'))

        for fail in motd.get('fail', []):
            self._intro.append(Error(fail + '\n'))


    def default(self, line):
        try:
            self.commands.execute(
                self.pupsrv, self, self.pupsrv.config, line)
        except PupyModuleExit:
            return

        if self.pupsrv.finishing.is_set():
            return True

    def init_readline(self):
        try:
            readline.read_history_file(".pupy_history")
        except Exception:
            pass
        self.init_completer()

    def cmdloop(self, intro=None):
        try:
            cmd.Cmd.cmdloop(self, intro)
        except KeyboardInterrupt as e:
            self.stdout.write('\n')
            self.cmdloop(intro="")

    def init_completer(self):
        readline.set_pre_input_hook(self.pre_input_hook)
        readline.set_completer_delims(" \t")

    def completenames(self, text, *ignored):
        return [
            x+' ' for x,_ in self.commands.list() if x.startswith(text)
        ]

    def pre_input_hook(self):
        #readline.redisplay()
        pass

    def emptyline(self):
        """ do nothing when an emptyline is entered """
        pass

    def do_EOF(self, arg):
        """ ignore EOF """
        self.stdout.write('\n')

    def do_help(self, arg):
        """ show this help """

        try:
            self.commands.execute(
                self.pupsrv, self, self.pupsrv.config, 'help {}'.format(arg))
        except PupyModuleExit:
            pass

    def acquire_io(self, requirements, amount):
        if requirements in (REQUIRE_REPL, REQUIRE_TERMINAL):
            if amount > 0:
                raise NotImplementedError('This UI does not support more than 1 repl or terminal')

            return [(self.stdin, self.stdout)]
        elif amount == 1:
            return [(None, ObjectStream(self.display))]
        else:
            return [(None, ObjectStream())]*amount

    def display(self, text):
        return self.stdout.write(hint_to_text(text).strip('\n')+'\n')

    def display_srvinfo(self, msg):
        return self.display(ServiceInfo(msg))

    def display_success(self, msg):
        return self.display(Success(msg))

    def display_error(self, msg):
        return self.display(Error(msg))

    def display_warning(self, msg):
        return self.display(Warning(msg))

    def display_info(self, msg):
        return self.display(Info(msg))

    def postcmd(self, stop, line):
        readline.write_history_file('.pupy_history')
        return stop

    def complete(self, text, state):
        if state == 0:
            import readline
            origline = readline.get_line_buffer()
            line = origline.lstrip()
            stripped = len(origline) - len(line)
            begidx = readline.get_begidx() - stripped
            endidx = readline.get_endidx() - stripped
            if begidx>0:
                cmd, args, foo = self.parseline(line)
                if cmd == '':
                    compfunc = self.completedefault
                else:
                    try:
                        #compfunc = getattr(self, 'complete_' + cmd)
                        compfunc = self.pupy_completer.complete
                    except AttributeError:
                        compfunc = self.completedefault
            else:
                compfunc = self.completenames
            self.completion_matches = compfunc(text, line, begidx, endidx)
        try:
            if self.completion_matches:
                return self.completion_matches[state]
        except IndexError:
            return None

    def _complete_path(self, path=None):
        "Perform completion of filesystem path."
        if not path:
            return os.listdir('.')
        dirname, rest = os.path.split(path)
        tmp = dirname if dirname else '.'
        res = [os.path.join(dirname, p)
                for p in os.listdir(tmp) if p.startswith(rest)]
        # more than one match, or single match which does not exist (typo)
        if len(res) > 1 or not os.path.exists(path):
            return res
        # resolved to a single directory, so return list of files below it
        if os.path.isdir(path):
            return [os.path.join(path, p) for p in os.listdir(path)]
        # exact file match terminates this completion
        return [path + ' ']

    def complete_read(self, text, line, begidx, endidx):
        tab = line.split(' ',1)
        if len(tab)>=2:
            return self._complete_path(tab[1])

class PupyCmdLoop(object):
    def __init__(self, pupyServer):
        self.cmd = PupyCmd(pupyServer)
        self.pupysrv = pupyServer
        self.stopped = Event()

    def loop(self):
        while not self.stopped.is_set() and not self.pupysrv.finished.is_set():
            try:
                self.cmd.cmdloop()
                self.stopped.set()
            except Exception as e:
                print(traceback.format_exc())
                time.sleep(0.1) #to avoid flood in case of exceptions in loop
                self.cmd.intro = []

        self.pupysrv.stop()

    def stop(self):
        self.stopped.set()
