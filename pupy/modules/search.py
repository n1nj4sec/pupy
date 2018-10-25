# -*- coding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.PupyCompleter import remote_path_completer
from modules.lib.utils.download import DownloadFronted

from threading import Event
from datetime import datetime

import dateparser

__class_name__="SearchModule"

@config(cat="gather")
class SearchModule(PupyModule):
    """ walk through a directory and recursively search a string into files """
    dependencies = {
        'all': [
            'pupyutils.search', 'scandir', 'transfer',
            'zipfile', 'tarfile', 'fsutils', 'scandir'
        ],
        'windows': ['junctions', 'ntfs_streams', 'pupwinutils', '_scandir'],
        'linux': ['xattr', '_scandir']
    }

    terminate = None

    @classmethod
    def init_argparse(cls):
        example = 'Examples:\n'
        example += '- Recursively search strings in files:\n'
        example += '>> run search -C .*ini passw.*=.*\n'
        example += '>> run search -C .* passw.*=.* -I\n'
        example += '- Recursively search string in file names:\n'
        example += '>> run search pwdfile.*\n'

        cls.arg_parser = PupyArgumentParser(prog="search", description=cls.__doc__, epilog=example)
        cls.arg_parser.add_argument(
            '-p', '--path', default='.',
            completer=remote_path_completer,
            help='root path to start (default: current path)')
        cls.arg_parser.add_argument('-m','--max-size', type=int, default=20000000, help='max file size (default 20 Mo)')
        cls.arg_parser.add_argument('-b', '--binary', action='store_true', help='search content inside binary files')
        cls.arg_parser.add_argument('-v', '--verbose', action='store_true', help='show errors')
        cls.arg_parser.add_argument('-C', '--content-only', action='store_true', help='show only results with content')
        cls.arg_parser.add_argument('-L', '--links', action='store_true', help='follow symlinks')
        cls.arg_parser.add_argument('-N', '--no-content', action='store_true', help='if string matches, output just filename')
        cls.arg_parser.add_argument('-I', '--insensitive', action='store_true', default=False, help='no case sensitive')
        cls.arg_parser.add_argument('-F', '--no-same-fs', action='store_true', default=False, help='do not limit search to same fs')

        cls.arg_parser.add_argument('-D', '--download', action='store_true', help='download found files (imply -N)')
        cls.arg_parser.add_argument('-A', '--archive', action='store_true', default=False, help='search in archive')

        cls.arg_parser.add_argument('-U', '--suid', action='store_true', default=False, help='Search SUID files')
        cls.arg_parser.add_argument('-G', '--sgid', action='store_true', default=False, help='Search SGID files')
        cls.arg_parser.add_argument('-u', '--user', help='Search files owned by user')
        cls.arg_parser.add_argument('-g', '--group', help='Search files owned by group')
        cls.arg_parser.add_argument('-O', '--own-world-accessible-write', action='store_true',
                                    help='Search accessible files for current process (write)')
        cls.arg_parser.add_argument('-t', '--timestamp-newer', help='Search files which are newer than date')
        cls.arg_parser.add_argument('-T', '--timestamp-older', help='Search files which are older than date')
        cls.arg_parser.add_argument('-X', '--xattr', default=False, nargs='?',
                                    help='Search files with extended attributes (can be specified)')

        cls.arg_parser.add_argument('filename', type=str, metavar='filename', help='regex to search (filename)')
        cls.arg_parser.add_argument('strings', nargs='*', default=[], type=str, metavar='string', help='regex to search (content)')

    def run(self, args):
        if args.download:
            args.no_content = True

        search = self.client.remote('pupyutils.search')

        newer = None
        older = None

        if args.timestamp_newer:
            try:
                newer = datetime.fromtimestamp(int(args.timestamp_newer))
            except ValueError:
                newer = dateparser.parse(args.timestamp_newer)

            newer = int((newer - datetime.fromtimestamp(0)).total_seconds())

        if args.timestamp_older:
            try:
                older = datetime.fromtimestamp(int(args.timestamp_older))
            except ValueError:
                older = dateparser.parse(args.timestamp_older)

            older = int((older - datetime.fromtimestamp(0)).total_seconds())

        s = search.Search(
            args.filename,
            strings=args.strings,
            max_size=args.max_size,
            root_path=args.path,
            follow_symlinks=args.links,
            no_content=args.no_content,
            case=args.insensitive,
            binary=args.binary,
            same_fs=not args.no_same_fs,
            search_in_archives=args.archive,
            content_only=args.content_only,
            suid=args.suid,
            sgid=args.sgid,
            user=args.user,
            group=args.group,
            owaw=args.own_world_accessible_write,
            newer=newer,
            older=older,
            xattr=args.xattr if args.xattr else args.xattr is not False
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

            def on_completed_info():
                self.success('Search completed, finish download engine')
                on_completed()

            self.terminate = downloader.interrupt
            self.info('Search+Download started. Use ^C to interrupt')
            s.run_cbs(on_data, on_completed_info, self.error)
            downloader.process()
            self.success('Search+Download completed')

        else:
            terminate = Event()

            def on_data(res):
                if terminate.is_set():
                    return

                if type(res) == tuple:
                    f, v = res
                    self.success(u'{}: {}'.format(f, v))
                else:
                    self.success(res)

            def on_completed():
                terminate.set()
                self.info('complete')

            self.terminate = terminate.set
            self.info('Search started. Use ^C to interrupt')

            error = self.error
            if not args.verbose:
                def error(x):
                    pass

            s.run_cb(on_data, on_completed, error)
            terminate.wait()
            s.stop()

    def interrupt(self):
        if self.terminate:
            self.terminate()
