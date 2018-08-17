# -*- coding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.utils.rpyc_utils import obtain

__class_name__="Zip"

@config(cat="admin")
class Zip(PupyModule):
    """ zip / unzip file or directory """

    dependencies = ['pupyutils.zip', 'zipfile']

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="zip", description=cls.__doc__)
        cls.arg_parser.add_argument('source', type=str, help='path of the source file or directory to zip')

        cls.arg_parser.add_argument('-l', action='store_true', help='list file  (default: zip file)')
        cls.arg_parser.add_argument('-u', action='store_true', help='unzip file (default: zip file)')
        cls.arg_parser.add_argument('-d', dest='destination', help='path of the destination file (default: current directory)')

    def nice_size(self, value):
        if value > 1024*1024*1024:
            return '{}G'.format(value/(1024*1024*1024))
        elif value > 1024*1024:
            return '{}M'.format(value/(1024*1024))
        elif value > 1024:
            return '{}K'.format(value/1024)
        else:
            return '{}B'.format(value)

    def run(self, args):
        if args.l:
            result, data = self.client.conn.modules["pupyutils.zip"].list(args.source)
            if result:
                data = obtain(data)
                log = args.source + ':\n' + '\n'.join(
                    '{:>8} {}'.format(self.nice_size(file_size), filename) for filename, file_size in data
                )
            else:
                log = data

        elif not args.u:
            result, log = self.client.conn.modules["pupyutils.zip"].zip(args.source, args.destination)
        else:
            result, log = self.client.conn.modules["pupyutils.zip"].unzip(args.source, args.destination)

        if result:
            self.success(log)
        else:
            self.error(log)
