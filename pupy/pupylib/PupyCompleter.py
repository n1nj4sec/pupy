# -*- coding: UTF8 -*-
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
import os
import os.path
import shlex
import re

def list_completer(l):
    def func(text, line, begidx, endidx):
        return [x+" " for x in l if x.startswith(text)]
    return func

def void_completer(text, line, begidx, endidx):
    return []

def path_completer(text, line, begidx, endidx):
    l=[]
    if not text:
        l=os.listdir(".")
    else:
        try:
            dirname=os.path.dirname(text)
            if not dirname:
                dirname="."
            basename=os.path.basename(text)
            for f in os.listdir(dirname):
                if f.startswith(basename):
                    if os.path.isdir(os.path.join(dirname,f)):
                        l.append(os.path.join(dirname,f)+os.sep)
                    else:
                        l.append(os.path.join(dirname,f)+" ")
        except Exception as e:
            pass
    return l

class PupyCompleter(object):
    def __init__(self, aliases, pupsrv):
        self.aliases=aliases
        self.pupsrv=pupsrv

    def get_module_completer(self, name):
        name=self.pupsrv.get_module_name_from_category(name)
        if name in self.aliases:
            name=self.aliases[name].split()[0]
        return self.pupsrv.get_module_completer(name)
        
    def complete(self, text, line, begidx, endidx):
        try:
            if line.startswith("run "):
                res=self.complete_run(text, line, begidx, endidx)
                if res is not None:
                    return res
                modname=line[4:].split()[0]
                completer_func=self.get_module_completer(modname).complete
                if completer_func:
                    return completer_func(text, line, begidx, endidx)
                else:
                    return []
            elif any([True for x in self.aliases if line.startswith(x+" ")]):
                modname=line.split()[0]
                completer_func=self.get_module_completer(modname).complete
                if completer_func:
                    return completer_func(text, line, begidx, endidx)
                else:
                    return []
                
        except Exception as e:
            #print e
            pass
            
    def complete_run(self, text, line, begidx, endidx):
        mline = line.partition(' ')[2]
        joker=1
        found_module=False
        #handle autocompletion of modules with --filter argument
        for x in shlex.split(mline):
            if x in ("-f", "--filter"):#arguments with a param
                joker+=1
            elif x in ("--bg",):#arguments without parameter
                pass
            else:
                joker-=1
            if not x.startswith("-") and joker==0:
                found_module=True
            if joker<0:
                return
        if ((len(text)>0 and joker==0) or (len(text)==0 and not found_module and joker<=1)):
            return self.pupsrv.categories.get_shell_list(text)

        
class PupyModCompleter(object):
    def __init__(self):
        self.conf= {
            "positional_args":[
            ],
            "optional_args":[
            ],
        }

    def add_positional_arg(self, names, **kwargs):
        """ names can be a string or a list to pass args aliases at once """
        if not type(names) is list and not type(names) is tuple:
            names=[names]
        for name in names:
            self.conf["positional_args"].append((name, kwargs))
    
    def add_optional_arg(self, names, **kwargs):
        """ names can be a string or a list to pass args aliases at once """
        if not type(names) is list and not type(names) is tuple:
            names=[names]
        for name in names:
            self.conf["optional_args"].append((name, kwargs))

    def get_optional_nargs(self, name):
        for n,kwargs in self.conf["optional_args"]:
            if name==n:
                if "action" in kwargs:
                    action=kwargs["action"]
                    if action=="store_true" or action=="store_false":
                        return 0
                break
        return 1

    def get_optional_args(self, nargs=None):
        if nargs is None:
            return [x[0] for x in self.conf["optional_args"]]
        else:
            return [x[0] for x in self.conf["optional_args"] if self.get_optional_nargs(x[0])==nargs]

    def get_last_text(self, text, line, begidx, endidx):
        try:
            return line[0:begidx-1].rsplit(' ',1)[1].strip()
        except Exception:
            return None

    def get_positional_arg_index(self, text, line, begidx, endidx):
        tab=shlex.split(line)
        positional_index=-1
        for i in range(0, len(tab)):
            if tab[i] in self.get_optional_args(nargs=0):
                continue
            elif tab[i] in self.get_optional_args(nargs=1):
                i+=1
                continue
            else:
                positional_index+=1
        if len(text)==0:
            positional_index+=1
        return positional_index

    def get_optional_args_completer(self, name):
        return [x[1]["completer"] for x in self.conf["optional_args"] if x[0]==name][0]

    def get_positional_args_completer(self, index):
        return self.conf["positional_args"][index][1]["completer"]

    def complete(self, text, line, begidx, endidx):
        last_text=self.get_last_text(text, line, begidx, endidx)
        if last_text in self.get_optional_args(nargs=1):
            return self.get_optional_args_completer(last_text)(text, line, begidx, endidx)
        if text.startswith("-"): #positional args completer
            return [x+" " for x in self.get_optional_args() if x.startswith(text)]
        else:
            try:
                positional_index=positional_index=self.get_positional_arg_index(text, line, begidx, endidx)-1
                if line.startswith("run "):  # -2 for "run" + "module_name" whereas -1 for aliases
                    positional_index-=1
                return self.get_positional_args_completer(positional_index)(text, line, begidx, endidx)
            except Exception as e:
                pass

            
        
