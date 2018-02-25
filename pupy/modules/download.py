# -*- coding: utf-8 -*-
from pupylib.PupyModule import *
from pupylib.PupyCompleter import *
from pupylib.PupyConfig import PupyConfig

from threading import Event
from StringIO import StringIO
from msgpack import Unpacker

import tarfile
import tempfile

import stat
import os
import os.path
import time
import zlib

__class_name__="DownloaderScript"

FIELDS_MAP = {
    x:y for x,y in enumerate([
        'st_mtime', 'st_gid', 'st_uid', 'st_mode', 'st_rdev'
    ])
}

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

    dependencies = [ 'transfer' ]

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

        self._completed = Event()
        self._terminate = None
        self._local_path = None
        self._remote_path = None
        self._files_count = None
        self._files_size = None
        self._last_directory = None
        self._current_file = None
        self._current_file_name = None
        self._current_file_dir = ''
        self._download_dir = None
        self._pending_symlinks = {}
        self._pending_metadata = {}
        self._archive = None

    def run(self, args):
        if args.calculate_size:
            du = self.client.remote('transfer', 'du', False)

            self._terminate = du(
                args.remote_file, self._callback, args.exclude, args.include,
                args.follow_symlinks, args.no_single_device)
            self._completed.wait()
            if self._files_count is not None and self._files_size is not None:
                self.success('Count: {} Size: {}'.format(
                    self._files_count, size_human_readable(self._files_size)))

            return

        if args.local_file:
            local_file = os.path.expandvars(args.local_file)

            if os.path.isdir(local_file):
                self._download_dir = local_file
            else:
                self._local_path = local_file
        else:
            config = PupyConfig()
            filesdir = config.get_folder('downloads', {'%c': self.client.short_name()})
            self._download_dir = filesdir

        if self._download_dir:
            if not os.path.exists(self._download_dir):
                os.makedirs(self._download_dir)

            self._last_directory = self._download_dir
        else:
            top_dir = os.path.dirname(self._local_path)
            if not os.path.isdir(top_dir):
                os.makedirs(top_dir)

        if args.archive:
            if self._download_dir:
                archive = args.remote_file.replace('/', '!').replace('\\', '!')
                while True:
                    if archive.startswith('!'):
                        archive = archive[1:]
                    elif archive.endswith('!'):
                        archive = archive[:-1]
                    else:
                        break

                archive += '.tgz'
                archive = os.path.join(self._download_dir, archive)
            else:
                archive = self._local_path

            if os.path.isfile(archive):
                os.unlink(archive)

            self._archive = tarfile.open(archive, mode='w:gz')

            self.info('downloading {} -> tgz:{}'.format(
                args.remote_file, archive))
        else:
            self.info('downloading {} -> {}'.format(
                args.remote_file, self._download_dir or self._local_path))

        transfer = self.client.remote('transfer', 'transfer', False)

        self._terminate = transfer(
            args.remote_file, self._callback, args.exclude, args.include,
            args.follow_symlinks, args.ignore_size, args.no_single_device)
        self._completed.wait()

        self.info('Completed!')

        if self._archive:
            self._archive.close()
            self._archive = None

    def _callback(self, data, exception):
        try:
            self._callback_unsafe(data, exception)
        except Exception, e:
            import traceback
            self.error('Internal error: {} / {}'.format(e, traceback.format_exc()))
            if self._terminate:
                self._terminate()

    def _callback_unsafe(self, data, exception):
        if self._completed.is_set():
            return

        if exception:
            self.error('Download failed: {}'.format(exception))

        if not data:
            self._completed.set()

        else:
            data = StringIO(data)

            for msg in Unpacker(data):
                self._handle_msg(msg)

    def _check_path(self, path):
        return os.path.sep.join(self._check_name(p) for p in path if p)

    def _check_name(self, name):
        if '\\..' in name or '../' in name or '/..' in name or '..\\' in name or name == '..':
            raise ValueError('Invalid path: {}'.format(name))
        return name

    def _get_path(self, msg):
        path = []
        if 'root' in msg:
            path = msg['root']

        if 'path' in msg:
            if type(msg['path']) in (str, unicode):
                path.append(msg['path'])
            else:
                path += msg['path']

        return self._check_path(path)

    def _meta(self, meta):
        return {
            FIELDS_MAP.get(x):y for x,y in meta.iteritems()
        }

    def _handle_msg(self, msg):
        msgtype = msg['type']

        if msgtype == 'size':
            self._files_count = msg['files']
            self._files_size = msg['size']
            self._remote_path = msg['path']

        elif msgtype == 'file':
            if self._current_file:
                raise ValueError('Invalid order of messages')

            self._current_file_name = self._get_path(msg)

            if 'stat' in msg:
                self._pending_metadata[self._current_file_name] = msg['stat']

            if self._last_directory:
                filepath = self._current_file_name
                filepath = os.path.join(self._last_directory, filepath)
            else:
                filepath = self._local_path

            if self._archive:
                self._current_file = tempfile.TemporaryFile()
            else:
                self._current_file = open(filepath, 'wb')

        elif msgtype == 'sparse':
            if not self._current_file:
                raise ValueError('Invalid order of messages')

            zeros = msg['data']
            self._current_file.seek(zeros-1, os.SEEK_CUR)
            self._current_file.write('\0')

        elif msgtype.endswith('content'):
            if not self._current_file:
                raise ValueError('Invalid order of messages')

            content = msg['data']
            if msgtype == 'zcontent':
                content = zlib.decompress(content)

            self._current_file.write(content)

        elif msgtype == 'exception':
            self.error('Error: {}/{}'.format(msg['exception'], msg['data']))

        elif msgtype == 'close' or msgtype == 'content-exception':
            if not self._current_file:
                raise ValueError('Invalid order of messages')

            if self._archive:
                self._current_file.flush()
                size = self._current_file.tell()

                info = tarfile.TarInfo()
                info.type = tarfile.REGTYPE
                info.name = os.path.join(self._current_file_dir, self._current_file_name)
                info.size = size

                if self._current_file_name in self._pending_metadata:
                    meta = self._meta(self._pending_metadata[self._current_file_name])
                    info.mtime = meta['st_mtime']
                    info.mode = meta['st_mode']
                    info.uid = meta['st_uid']
                    info.gid = meta['st_gid']

                self._current_file.seek(0, os.SEEK_SET)
                self._archive.addfile(info, self._current_file)

            self._current_file.close()
            self._current_file = None

            if self._current_file_name in self._pending_metadata:
                del self._pending_metadata[self._current_file_name]

            if msgtype == 'content-exception':
                self.warning('{} - {}'.format(msg['data'], msg['exception']))

        elif msgtype == 'dirview':
            dirview = msg['data']
            self._current_file_dir = self._get_path(dirview)
            self._last_directory = os.path.join(
                self._download_dir, self._current_file_dir)

            if not self._archive:
                if not os.path.isdir(self._last_directory):
                    os.makedirs(self._last_directory)

            for d, meta in dirview['dirs'].iteritems():
                meta = self._meta(meta)

                if self._archive:
                    info = tarfile.TarInfo()
                    info.name = os.path.join(self._current_file_dir, self._check_name(d))
                    info.type = tarfile.DIRTYPE
                    info.mtime = meta['st_mtime']
                    info.mode = meta['st_mode']
                    info.uid = meta['st_uid']
                    info.gid = meta['st_gid']
                    self._archive.addfile(info)

                else:
                    subdir = os.path.join(self._last_directory, self._check_name(d))
                    if not os.path.isdir(subdir):
                        os.mkdir(subdir)

            for z, meta in dirview['empty'].iteritems():
                meta = self._meta(meta)

                if self._archive:
                    info = tarfile.TarInfo()
                    info.name = os.path.join(self._current_file_dir, self._check_name(z))
                    info.type = tarfile.REGTYPE
                    info.mtime = meta['st_mtime']
                    info.mode = meta['st_mode']
                    info.uid = meta['st_uid']
                    info.gid = meta['st_gid']
                    info.size = 0
                    self._archive.addfile(info)

                else:
                    with open(os.path.join(self._last_directory, self._check_name(z)), 'w'):
                        pass

            for s, lnk in dirview['syms'].iteritems():
                if self._archive:
                    info = tarfile.TarInfo()
                    info.name = os.path.join(self._current_file_dir, self._check_name(s))

                    info.type = tarfile.SYMTYPE
                    info.linkname = os.path.sep.join(lnk)
                    self._archive.addfile(info)

                else:
                    s = os.path.join(self._last_directory, self._check_name(s))
                    if os.path.islink(s) or os.path.exists(s):
                        os.unlink(s)

                    symto = os.path.relpath(
                        os.path.join(self._last_directory, os.path.sep.join(x for x in lnk if x)),
                        start=self._last_directory
                    )

                    os.symlink(symto, s)

            if self._archive:
                for s, (meta, lnk) in dirview['hards'].iteritems():
                    meta = self._meta(meta)

                    info = tarfile.TarInfo()
                    info.name = os.path.join(self._current_file_dir, self._check_name(s))
                    info.type = tarfile.SYMTYPE
                    info.linkname = os.path.sep.join(lnk)
                    info.mtime = meta['st_mtime']
                    info.mode = meta['st_mode']
                    info.uid = meta['st_uid']
                    info.gid = meta['st_gid']

                    self._archive.addfile(info)

                for spec, meta in dirview['specials'].iteritems():
                    meta = self._meta(meta)

                    info = tarfile.TarInfo()
                    info.name = os.path.join(self._current_file_dir, self._check_name(spec))

                    device = False

                    if meta['st_mode'] & 0o170000 == stat.S_IFIFO:
                        info.type = tarfile.FIFOTYPE
                    elif meta['st_mode'] & 0o170000 == stat.S_IFBLK:
                        info.type = tarfile.BLKTYPE
                        device = True
                    elif meta['st_mode'] & 0o170000 == stat.S_IFCHR:
                        info.type = tarfile.CHRTYPE
                        device = True
                    elif meta['st_mode'] & 0o170000 == stat.S_IFSOCK:
                        info.type = tarfile.CONTTYPE
                    else:
                        continue

                    info.mtime = meta['st_mtime']
                    info.mode = meta['st_mode']
                    info.uid = meta['st_uid']
                    info.gid = meta['st_gid']

                    if device and hasattr(os, "major") and hasattr(os, "minor"):
                        info.devmajor = os.major(meta['st_rdev'])
                        info.devminor = os.minor(meta['st_rdev'])

                    self._archive.addfile(info)

            self._pending_metadata = dirview['files']


    def interrupt(self):
        if self._terminate:
            self._terminate()
        self._completed.set()

    def __del__(self):
        if self._current_file is not None:
            self._current_file.close()
            self._current_file = None

        if self._archive is not None:
            self._archive.close()
            self._archive = None
