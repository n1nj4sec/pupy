# -*- coding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.PupyCompleter import remote_path_completer
from modules.lib.utils.download import DownloadFronted

from threading import Event

__class_name__="SearchModule"

@config(cat="gather")
class SearchModule(PupyModule):
    """ walk through a directory and recursively search a string into files """
    dependencies = {
        'all': [ 'pupyutils.search', 'scandir', 'transfer' ],
        'windows': [ 'junctions' ],
    }

    terminate = None

    @classmethod
    def init_argparse(cls):
        example = 'Examples:\n'
        example += '- Recursively search strings in files:\n'
        example += '>> run search .*ini passw.*=.*\n'
        example += '>> run search .* passw.*=.* -I\n'
        example += '- Recursively search string in file names:\n'
        example += '>> run search pwdfile.*\n'

        cls.arg_parser = PupyArgumentParser(prog="search", description=cls.__doc__, epilog=example)
        cls.arg_parser.add_argument(
            '-p', '--path', default='.',
            completer=remote_path_completer,
            help='root path to start (default: current path)')
        cls.arg_parser.add_argument('-m','--max-size', type=int, default=20000000, help='max file size (default 20 Mo)')
        cls.arg_parser.add_argument('-b', '--binary', action='store_true', help='search content inside binary files')
        cls.arg_parser.add_argument('-C', '--content-only', action='store_true', help='show only results with content')
        cls.arg_parser.add_argument('-L', '--links', action='store_true', help='follow symlinks')
        cls.arg_parser.add_argument('-D', '--download', action='store_true', help='download found files (imply -N)')
        cls.arg_parser.add_argument('-N', '--no-content', action='store_true', help='if string matches, output just filename')
        cls.arg_parser.add_argument('-I', '--insensitive', action='store_true', default=False, help='no case sensitive')
        cls.arg_parser.add_argument('filename', type=str, metavar='filename', help='regex to search (filename)')
        cls.arg_parser.add_argument('strings', nargs='*', default=[], type=str, metavar='string', help='regex to search (content)')

    def run(self, args):
        if args.download:
            args.no_content = True

        search = self.client.remote('pupyutils.search')

        s = search.Search(
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
            config = self.client.pupsrv.config
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
            terminate = Event()

            def on_data(res):
                if terminate.is_set():
                    return

                if args.strings and not args.no_content:
                    if type(res) == tuple:
                        f, v = res
                        if type(f) == unicode:
                            f = f.encode('utf-8')
                        if type(v) == unicode:
                            v = v.encode('utf-8')
                        self.success('{}: {}'.format(f, v))
                    elif not args.content_only:
                        self.success(res)
                else:
                    self.success(res)

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
