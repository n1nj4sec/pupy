# -*- coding: UTF8 -*-
from pupylib.PupyModule import *
from pupylib.utils.rpyc_utils import redirected_stdio

__class_name__="Zip"

@config(cat="admin")
class Zip(PupyModule):
    """ zip / unzip file or directory """

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="zip", description=self.__doc__)
        self.arg_parser.add_argument('source', type=str, help='path of the source file or directory to zip')

        self.arg_parser.add_argument('-u', action='store_true', help='unzip file (default: zip file)')
        self.arg_parser.add_argument('-d', dest='destination', help='path of the destination file (default: current directory)')

    def run(self, args):
        self.client.load_package("pupyutils.zip")
        with redirected_stdio(self.client.conn):
            # zip
            if not args.u:
                self.client.conn.modules["pupyutils.zip"].zip(args.source, args.destination)
            # unzip
            else:
                self.client.conn.modules["pupyutils.zip"].unzip(args.source, args.destination)