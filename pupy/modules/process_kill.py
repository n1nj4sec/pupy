# -*- coding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser

__class_name__="KillModule"

@config(cat="general")
class KillModule(PupyModule):
    """ kill a process """

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="kill", description=cls.__doc__)
        cls.arg_parser.add_argument('-s', '--signal', type=int, default=9, help='signal code (non windows)')
        cls.arg_parser.add_argument('pids', type=int, nargs='+', help='pids to kill')

    def run(self, args):
        kill = self.client.remote('os', 'kill', False)

        for pid in args.pids:
            try:
                kill(pid, args.signal)
                self.success('Killed: {} (sig={})'.format(pid, args.signal))

            except Exception, e:
                self.error('Failed: {}: {}'.format(pid, e))
