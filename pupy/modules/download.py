# -*- coding: utf-8 -*-
from pupylib.PupyModule import *
from pupylib.PupyCompleter import *

from modules.lib.utils.download import DownloadFronted

__class_name__="DownloaderScript"

def size_human_readable(num, suffix='B'):
    try:
        num = int(num)
        for unit in ['','Ki','Mi','Gi','Ti','Pi','Ei','Zi']:
            if abs(num) < 1024.0:
                return "%3.1f %s%s" % (num, unit, suffix)
            num /= 1024.0
        return "%.1f %s%s" % (num, 'Yi', suffix)
    except:
        return '0.00 B'

@config(category="manage")
class DownloaderScript(PupyModule):
    """ download a file/directory from a remote system """

    dependencies = {
        'all': [ 'transfer', 'scandir' ],
        'windows': [ 'junctions' ]
    }

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog='download', description=self.__doc__)
        self.arg_parser.add_argument('-v', '--verbose', action='store_true', default=False,
                                         help='Be verbose during download')
        self.arg_parser.add_argument('-a', '--archive', action='store_true', default=False,
                                         help='Store to archive (use this only for dirs)')
        self.arg_parser.add_argument('-i', '--include', help='Regex to include files')
        self.arg_parser.add_argument('-e', '--exclude', help='Regex to exclude files')
        self.arg_parser.add_argument('-F', '--follow-symlinks', action='store_true', help='Follow symlinks')
        self.arg_parser.add_argument('-I', '--ignore-size', action='store_true', help='Ignore st_size')
        self.arg_parser.add_argument('-X', '--no-single-device', action='store_false', default=True,
                                     help='Allow to touch another devices (st_rdev)')
        self.arg_parser.add_argument('-S', '--calculate-size', action='store_true', help='Calculate size only')

        self.arg_parser.add_argument('remote_file', metavar='<remote_path>')
        self.arg_parser.add_argument('local_file', nargs='?', metavar='<local_path>', completer=path_completer)

        self._downloader = None

    def run(self, args):
        self._downloader = DownloadFronted(
            self.client,
            args.exclude, args.include, args.follow_symlinks, args.ignore_size, args.no_single_device,
            False, self.info if args.verbose else None, self.error
        )

        if args.calculate_size:
            count, size = self._downloader.du(args.remote_file)
            if count is not None and size is not None:
                self.success('Files: {} Size: {}'.format(count, size_human_readable(size)))
        else:
            self._downloader.download(
                args.remote_file,
                args.local_file,
                args.archive
            )
            if not args.verbose:
                self.success('{}'.format(self._downloader.dest_file))

    def interrupt(self):
        if self._downloader:
            self._downloader.interrupt()
