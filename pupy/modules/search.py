# -*- coding: utf-8 -*-
from pupylib.PupyModule import *
import os
import threading
from pupylib.utils.term import colorize

from modules.lib.utils.download import DownloadFronted

__class_name__="SearchModule"

@config(cat="gather")
class SearchModule(PupyModule):
    """ walk through a directory and recursively search a string into files """
    dependencies = {
        'all': [ 'pupyutils.search', 'scandir', 'transfer' ],
        'windows': [ 'junctions' ],
    }

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
        self.arg_parser.add_argument('filename', type=str, metavar='filename', help='regex to search (filename)')
        self.arg_parser.add_argument('strings', nargs='*', default=[], type=str, metavar='string', help='regex to search (content)')

    def run(self, args):
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

        if args.download:
            config = self.client.pupsrv.config or PupyConfig()
            download_folder = config.get_folder('searches', {'%c': self.client.short_name()})

            downloader = DownloadFronted(
                self.client,
                honor_single_file_root=True,
                verbose=self.info,
                error=self.error
            )

            on_data, on_completed = downloader.create_download_callback(download_folder)
            self.terminate = downloader.interrupt
            self.info('Search+Download started. Use ^C to interrupt')
            s.run_cbs(on_data, on_completed, self.error)
            downloader.process()
            self.info('complete')

        else:
            terminate = threading.Event()

            def on_data(res):
                if terminate.is_set():
                    return

                if args.strings and not args.no_content:
                    if type(res) == tuple:
                        self.success('{}: {}'.format(*res))
                    else:
                        self.success('{}'.format(res))
                else:
                    self.success('{}'.format(res))

            def on_completed():
                terminate.set()
                self.info('complete')

            self.terminate = terminate.set
            self.info('Search started. Use ^C to interrupt')
            s.run_cb(on_data, on_completed, self.error)
            terminate.wait()
            s.stop()

    def interrupt(self):
        if self.terminate:
            self.terminate()
