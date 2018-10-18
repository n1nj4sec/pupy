# -*- coding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.PupyCompleter import remote_path_completer, path_completer

from modules.lib.utils.download import DownloadFronted

from os import path, devnull
from subprocess import Popen

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
        'all': ['transfer', 'scandir', 'zipfile', 'tarfile'],
        'windows': ['junctions']
    }

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog='download', description=cls.__doc__)
        cls.arg_parser.add_argument('-v', '--verbose', action='store_true', default=False,
                                         help='Be verbose during download')
        cls.arg_parser.add_argument('-O', '--open', action='store_true', default=False,
                                         help='Open file with xdg-open')
        cls.arg_parser.add_argument('-a', '--archive', action='store_true', default=False,
                                         help='Store to archive (use this only for dirs)')
        cls.arg_parser.add_argument('-i', '--include', help='Regex to include files')
        cls.arg_parser.add_argument('-e', '--exclude', help='Regex to exclude files')
        cls.arg_parser.add_argument('-F', '--follow-symlinks', action='store_true', help='Follow symlinks')
        cls.arg_parser.add_argument('-I', '--ignore-size', action='store_true', help='Ignore st_size')
        cls.arg_parser.add_argument('-X', '--no-single-device', action='store_false', default=True,
                                     help='Allow to touch another devices (st_rdev)')
        cls.arg_parser.add_argument('-S', '--calculate-size', action='store_true', help='Calculate size only')

        cls.arg_parser.add_argument('remote_file', metavar='<remote_path>', completer=remote_path_completer)
        cls.arg_parser.add_argument('local_file', nargs='?', metavar='<local_path>', completer=path_completer)

    def run(self, args):
        self._downloader = DownloadFronted(
            self.client,
            args.exclude, args.include, args.follow_symlinks, args.ignore_size, args.no_single_device,
            False, self.info if args.verbose else None, self.success, self.error
        )

        if args.calculate_size:
            obj = self.client.remote('transfer')
            count, size = self._downloader.du(args.remote_file, obj)
            if count is not None and size is not None:
                self.success('Files: {} Size: {}'.format(count, size_human_readable(size)))
        else:
            self._downloader.download(
                args.remote_file,
                args.local_file,
                args.archive
            )

            if args.verbose:
                self.info('Destination folder: {}'.format(self._downloader.dest_file))

            if args.open and path.exists(self._downloader.dest_file):
                viewer = self.config.get('default_viewers', 'xdg_open') or 'xdg-open'
                if args.verbose:
                    self.info('Open file {} with {}'.format(self._downloader.dest_file, viewer))
                with open(devnull, 'w') as DEVNULL:
                    Popen(
                        [viewer, self._downloader.dest_file],
                        stdout=DEVNULL, stderr=DEVNULL)

    def interrupt(self):
        if self._downloader:
            self._downloader.interrupt()
