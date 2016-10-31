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
try:
    import ConfigParser as configparser
except ImportError:
    import configparser
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
import argparse
from pupysh import __version__, __date__
import copy
from functools import partial

BANNER="""
            _____                    _       _ _
 ___ ___   |  _  |_ _ ___ _ _    ___| |_ ___| | |   ___ ___
|___|___|  |   __| | | . | | |  |_ -|   | -_| | |  |___|___|
           |__|  |___|  _|_  |  |___|_|_|___|_|_|
                     |_| |___|

                   %s (%s)
"""%(__version__, __date__)

BANNER_INFO="""
Author:           Nicolas VERDIER  < @n1nj4sec > (contact@n1nj4.eu)
Bleeding edge:    https://github.com/n1nj4sec/pupy
"""


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
            if not i in size_dic:
                size_dic[i]=len(k)
            elif size_dic[i]<len(k):
                size_dic[i]=len(k)
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
    def __init__(self, pupsrv, configFile="pupy.conf"):
        cmd.Cmd.__init__(self)
        self.pupsrv=pupsrv
        self.pupsrv.register_handler(self)
        self.config = configparser.ConfigParser()
        self.config.read(configFile)
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

        self.intro += "\n"+self.format_srvinfo("Server started on%s port %s with transport %s%s"%((" "+self.pupsrv.address if self.pupsrv.address else ""), self.pupsrv.port, self.pupsrv.transport, (" and transport_args=%s"%repr(self.pupsrv.transport_kwargs) if self.pupsrv.transport_kwargs else ""))).rstrip("\n")

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
                    res+=value.ljust(colsize[name]+2+utf8align)
                res+="\n"
        return res

    def default(self, line):
        tab=line.split(" ",1)
        if tab[0] in self.aliases:
            arg_parser = PupyArgumentParser(prog=tab[0], add_help=False)
            arg_parser.add_argument('-f', '--filter', metavar='<client filter>', help="filter to a subset of all clients. All fields available in the \"info\" module can be used. example: run get_info -f 'platform:win release:7 os_arch:64'")
            arg_parser.add_argument('--bg', action='store_true', help="run in background")
            arg_parser.add_argument('arguments', nargs=argparse.REMAINDER, metavar='<arguments>', help="module arguments")
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
                cmds_doc.append((name, self.pupsrv.get_module(self.aliases[name]).__doc__))

            self.stdout.write("%s\n"%str(self.doc_header))
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

    def do_sessions(self, arg):
        """ list/interact with established sessions """
        arg_parser = PupyArgumentParser(prog='sessions', description=self.do_sessions.__doc__)
        arg_parser.add_argument('-i', '--interact', metavar='<filter>', help="change the default --filter value for other commands")
        arg_parser.add_argument('-g', '--global-reset', action='store_true', help="reset --interact to the default global behavior")
        arg_parser.add_argument('-l', dest='list', action='store_true', help='List all active sessions')
        arg_parser.add_argument('-k', dest='kill', metavar='<id>', type=int, help='Kill the selected session')
        arg_parser.add_argument('-K', dest='killall', action='store_true', help='Kill all sessions')
        arg_parser.add_argument('-d', dest='drop', metavar='<id>', type=int, help='Drop the connection (abruptly close the socket)')
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

        elif modargs.list or not arg:
            client_list=self.pupsrv.get_clients_list()
            self.display(PupyCmd.table_format([x.desc for x in client_list], wl=["id", "user", "hostname", "platform", "release", "os_arch","proc_arch","intgty_lvl","address"]))

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

    def do_run(self, arg):
        """ run a module on one or multiple clients"""
        arg_parser = PupyArgumentParser(prog='run', description='run a module on one or multiple clients')
        arg_parser.add_argument('module', metavar='<module>', help="module")
        arg_parser.add_argument('-f', '--filter', metavar='<client filter>', default=self.default_filter ,help="filter to a subset of all clients. All fields available in the \"info\" module can be used. example: run get_info -f 'platform:win release:7 os_arch:64'")
        arg_parser.add_argument('--bg', action='store_true', help="run in background")
        arg_parser.add_argument('arguments', nargs=argparse.REMAINDER, metavar='<arguments>', help="module arguments")
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
                pj=PupyJob(self.pupsrv,"%s %s"%(modargs.module, args))
                if len(l)==1 and not modargs.bg and not mod.daemon:
                    ps=mod(l[0], pj, stdout=self.stdout)
                    pj.add_module(ps)
                    interactive=True
                else:
                    for c in l:
                        ps=mod(c, pj)
                        pj.add_module(ps)
            try:
                pj.start(args)
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
        if pj:
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

    def do_exit(self, arg):
        """ Quit Pupy Shell """
        sys.exit()

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
