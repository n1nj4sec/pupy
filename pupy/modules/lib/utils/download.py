# -*- coding: utf-8 -*-

from threading import Event
from StringIO import StringIO
from msgpack import Unpacker

from Queue import Queue

import tarfile
import tempfile

import stat
import os
import os.path
import zlib
import errno

FIELDS_MAP = {
    x:y for x,y in enumerate([
        'st_mtime', 'st_gid', 'st_uid', 'st_mode', 'st_rdev'
    ])
}

F_TYPE     = 0
F_PATH     = 1
F_FILES    = 2
F_SIZE     = 3
F_DATA     = 4
F_EXC      = 5
F_STAT     = 6
F_ROOT     = 7

T_SIZE     = 0
T_FILE     = 1
T_CONTENT  = 2
T_ZCONTENT = 3
T_SPARSE   = 4
T_CLOSE    = 5
T_C_EXC    = 6
T_DIRVIEW  = 7
T_EXC      = 8
T_FINISH   = 9

D_ROOT     = 0
D_DIRS     = 1
D_SYMS     = 2
D_HARDS    = 3
D_SPECIALS = 4
D_EMPTY    = 5
D_FILES    = 6

class DownloadFronted(object):
    def __init__(self, client, exclude=None, include=None, follow_symlinks=False,
                 ignore_size=False, no_single_device=False,
                     honor_single_file_root=False, verbose=None, success=None, error=None):

        self.client = client

        self._exclude = exclude
        self._include = include
        self._follow_symlinks = follow_symlinks
        self._ignore_size = ignore_size
        self._no_single_device = no_single_device
        self._honor_single_file_root = honor_single_file_root

        self._verbose = verbose
        self._success = success
        self._error = error

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
        self._current_file_dir_raw = ''
        self._download_dir = None
        self._pending_symlinks = {}
        self._pending_metadata = {}
        self._archive = None
        self._archive_file = None
        self._queue = Queue()

        self._last_downloaded_dest = None

        self._transfer_stop = None

    def du(self, remote_file, obj):
        self._terminate = obj.du(
            remote_file, self._submit_message, self._exclude, self._include,
            self._follow_symlinks, self._no_single_device)

        self._process_queue()
        self._terminate = None

        if self._files_count is not None and self._files_size is not None:
            return self._files_count, self._files_size
        else:
            return None, None

    def _setup_context(self, remote_file, local_file, archive):
        if local_file:
            local_file = os.path.expandvars(local_file)

            if os.path.isdir(local_file):
                self._download_dir = local_file
            else:
                self._local_path = local_file
        else:
            filesdir = self.client.pupsrv.config.get_folder(
                'downloads', {'%c': self.client.short_name()})

            self._download_dir = filesdir

        if self._download_dir:
            if not os.path.exists(self._download_dir):
                os.makedirs(self._download_dir)

            self._last_directory = self._download_dir
        else:
            top_dir = os.path.dirname(self._local_path)
            if not os.path.isdir(top_dir):
                os.makedirs(top_dir)

        if archive:
            if self._download_dir and remote_file:
                archive = remote_file.replace('/', '!').replace('\\', '!')
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

            self._archive_file = archive
            self._archive = tarfile.open(self._archive_file, mode='w:gz')

    @property
    def dest_file(self):
        return self._archive_file or self._last_downloaded_dest \
            or self._download_dir or self._local_path

    def download(self, remote_file, local_file=None, archive=False):
        self._setup_context(remote_file, local_file, archive)

        transfer = self.client.remote('transfer', 'transfer', False)
        self._terminate = transfer(
            remote_file, self._submit_message, self._exclude, self._include,
            self._follow_symlinks, self._ignore_size, self._no_single_device)

        if self._verbose:
            if self._archive:
                self._verbose('Download: {} -> tgz:{}'.format(
                    remote_file, self.dest_file))
            else:
                self._verbose('Download: {} -> {}'.format(
                    remote_file, self.dest_file))

        self.process()
        self._terminate = None

    def create_download_callback(self, local_file=None, archive=False):
        self._setup_context(None, local_file, archive)

        transfer_closure = self.client.remote('transfer', 'transfer_closure', False)

        closure, self._transfer_stop, self._terminate = transfer_closure(
            self._submit_message, self._exclude, self._include,
            self._follow_symlinks, self._ignore_size, self._no_single_device)

        return closure, self._transfer_stop

    def stop(self):
        if self._transfer_stop:
            self._transfer_stop()
            self._transfer_stop = None

    def process(self):
        self._process_queue()
        if self._archive:
            self._archive.close()
            self._archive = None

    def _process_queue(self):
        while not self._completed.is_set():
            data, exception = self._queue.get()
            self._callback(data, exception)

    def _submit_message(self, data, exception):
        if not self._completed.is_set():
            self._queue.put((data, exception))

    def _callback(self, data, exception):
        try:
            self._callback_unsafe(data, exception)
        except Exception, e:
            if self._error:
                import traceback
                self._error('Internal error: {} / {}'.format(e, traceback.format_exc()))

            if self._terminate:
                self._terminate()

    def _callback_unsafe(self, data, exception):
        if self._completed.is_set():
            return

        if exception and self._error:
            self._error('{}'.format(exception))

        if not data:
            self._completed.set()

        else:
            data = StringIO(data)

            for msg in Unpacker(data):
                if self._completed.is_set():
                    break

                self._handle_msg(msg)

    def _split_path(self, path):
        _path = []
        for portion in path.split('/'):
            _path.append(portion)

        path = _path
        _path = []

        for p in path:
            for portion in p.split('\\'):
                _path.append(portion)

        return _path

    def _check_path(self, path):
        return os.path.sep.join(self._check_name(p) for p in self._split_path(path) if p)

    def _check_name(self, name):
        if os.path.sep in name or name == '..':
            raise ValueError('Invalid path: {}'.format(name))
        return name

    def _get_path(self, msg):
        path = ''
        msgtype = msg[F_TYPE]

        if msgtype == T_DIRVIEW:
            path = msg[F_DATA][D_ROOT]
        elif msgtype == T_FILE:
            if F_ROOT in msg and self._honor_single_file_root:
                path = msg[F_ROOT]

            if F_PATH in msg:
                path = os.path.join(path, msg[F_PATH])
        else:
            raise ValueError('Invalid Message passed to _get_path')

        return self._check_path(path)

    def _meta(self, meta):
        return {
            FIELDS_MAP[x]:y for x,y in enumerate(meta)
        }

    def _handle_msg(self, msg):
        msgtype = msg[F_TYPE]

        if msgtype == T_SIZE:
            self._files_count = msg[F_FILES]
            self._files_size = msg[F_SIZE]
            self._remote_path = msg[F_PATH]

        elif msgtype == T_FILE:
            if self._current_file:
                raise ValueError('Invalid order of messages')

            self._current_file_name = self._get_path(msg)

            if F_STAT in msg:
                self._pending_metadata[self._current_file_name] = msg[F_STAT]

            if self._last_directory:
                filepath = self._current_file_name
                filepath = os.path.join(self._last_directory, filepath)
            else:
                filepath = self._local_path

            if F_ROOT in msg:
                if self._honor_single_file_root and not self._archive:
                    try:
                        os.makedirs(os.path.dirname(filepath))
                    except OSError, e:
                        if e.errno != errno.EEXIST:
                            if self._error:
                                self._error('{}: {}'.format(filepath, e))
                    except Exception, e:
                        if self._error:
                            self._error('{}: {}'.format(filepath, e))

                self._last_downloaded_dest = filepath

            if self._archive:
                self._current_file = tempfile.TemporaryFile()
                if self._verbose:
                    self._verbose('{}'.format(self._current_file_name))
            else:
                filedir = os.path.dirname(filepath)

                # Workaround for archives unpacking
                if not os.path.isdir(filedir):
                    if os.path.isfile(filedir):
                        os.unlink(filedir)

                    os.makedirs(filedir)

                self._current_file = open(filepath, 'wb')

                if self._verbose:
                    self._verbose('{}'.format(filepath))

        elif msgtype == T_SPARSE:
            if not self._current_file:
                raise ValueError('Invalid order of messages')

            zeros = msg[F_DATA]
            self._current_file.seek(zeros-1, os.SEEK_CUR)
            self._current_file.write('\0')

        elif msgtype in (T_CONTENT, T_ZCONTENT):
            if not self._current_file:
                raise ValueError('Invalid order of messages')

            content = msg[F_DATA]
            if msgtype == T_ZCONTENT:
                content = zlib.decompress(content)

            self._current_file.write(content)

        elif msgtype == T_EXC:
            if self._error:
                self._error('Error: {}/{}'.format(msg[F_EXC], msg[F_DATA]))

        elif msgtype == T_FINISH:
            if self._success:
                self._success('Completed: {} -> {}'.format(
                    msg[F_DATA], self.dest_file))

        elif msgtype in (T_CLOSE, T_C_EXC):
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

            if msgtype == T_C_EXC:
                if self._verbose:
                    self._verbose('{} - {}'.format(msg[F_DATA], msg[F_EXC]))

        elif msgtype == T_DIRVIEW:
            dirview = msg[F_DATA]
            self._current_file_dir = self._get_path(msg)
            self._current_file_dir_raw = dirview[D_ROOT]

            if not self._archive:
                if not self._download_dir:
                    self._download_dir = self._local_path

                self._last_directory = os.path.join(
                    self._download_dir, self._current_file_dir)

                if not os.path.isdir(self._last_directory):
                    os.makedirs(self._last_directory)

            for d, meta in dirview[D_DIRS]:
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

            for z, meta in dirview[D_EMPTY]:
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
                    with open(os.path.join(self._last_directory, self._check_name(z)), 'wb'):
                        pass

            for s, lnk in dirview[D_SYMS]:
                if self._archive:
                    info = tarfile.TarInfo()
                    info.name = os.path.join(self._current_file_dir, self._check_name(s))

                    info.type = tarfile.SYMTYPE
                    info.linkname = lnk
                    self._archive.addfile(info)

                else:
                    s = os.path.join(self._last_directory, self._check_name(s))
                    if os.path.islink(s) or os.path.exists(s):
                        os.unlink(s)

                    lnk = self._split_path(lnk)
                    symto = os.path.sep.join(lnk)

                    if self.client.is_windows():
                        if symto.startswith(os.path.sep) or ':' in symto:
                            symto = os.path.relpath(
                                symto.upper(),
                                start=self._current_file_dir.upper()
                            ).split(os.path.sep)

                            for i in xrange(min(len(symto), len(lnk))):
                                if symto[-i-1] == '..':
                                    break

                                if symto[-i-1].upper() == lnk[-i-1].upper():
                                    symto[-i-1] = lnk[-i-1]

                            symto = os.path.sep.join(symto)

                    else:
                        if symto.startswith(os.path.sep):
                            symto = os.path.relpath(
                                symto,
                                start=self._current_file_dir_raw
                            )

                    os.symlink(symto, s)

            if self._archive:
                for s, meta, lnk in dirview[D_HARDS]:
                    meta = self._meta(meta)

                    info = tarfile.TarInfo()
                    info.name = os.path.join(self._current_file_dir, self._check_name(s))
                    info.type = tarfile.SYMTYPE
                    info.linkname = lnk
                    info.mtime = meta['st_mtime']
                    info.mode = meta['st_mode']
                    info.uid = meta['st_uid']
                    info.gid = meta['st_gid']

                    self._archive.addfile(info)

                for spec, meta in dirview[D_SPECIALS]:
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

            self._pending_metadata = dirview[D_FILES]

    def interrupt(self):
        if self._completed.is_set():
            return

        try:
            if self._terminate:
                self._terminate()

                self._completed.wait(5)
                self._terminate = None

        finally:
            self._completed.set()
            self._submit_message(None, None)

    def __del__(self):
        if self._current_file is not None:
            self._current_file.close()
            self._current_file = None

        if self._archive is not None:
            self._archive.close()
            self._archive = None

        self._transfer = None
        self._worker = None
