# -*- coding: utf-8 -*-

from threading import Thread, Event
from StringIO import StringIO
from msgpack import Unpacker

from Queue import Queue

import tarfile
import tempfile

import stat
import os
import os.path
import time
import zlib
import errno

FIELDS_MAP = {
    x:y for x,y in enumerate([
        'st_mtime', 'st_gid', 'st_uid', 'st_mode', 'st_rdev'
    ])
}

class DownloadFronted(object):
    def __init__(self, client, exclude=None, include=None, follow_symlinks=False,
                 ignore_size=False, no_single_device=False,
                     honor_single_file_root=False, verbose=None, error=None):

        self.client = client

        self._exclude = exclude
        self._include = include
        self._follow_symlinks = follow_symlinks
        self._ignore_size = ignore_size
        self._no_single_device = no_single_device
        self._honor_single_file_root = honor_single_file_root

        self._verbose = verbose
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

    def du(self, remote_file):
        du = self.client.remote('transfer', 'du', False)

        self._terminate = du(
            remote_file, self._submit_message, self._exclude, self._include,
            self._follow_symlinks, self._no_single_device)

        self._process_queue()

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
        return self._last_downloaded_dest or self._archive_file \
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
            self._error('Download failed: {}'.format(exception))

        if not data:
            self._completed.set()

        else:
            data = StringIO(data)

            for msg in Unpacker(data):
                if self._completed.is_set():
                    break

                self._handle_msg(msg)

    def _check_path(self, path):
        _initial = path

        _path = []
        for p in path:
            for portion in p.split('/'):
                _path.append(portion)

        path = _path
        _path = []

        for p in path:
            for portion in p.split('\\'):
                _path.append(portion)

        path = os.path.sep.join(self._check_name(p) for p in _path if p)
        return path

    def _check_name(self, name):
        if '\\' in name or '/' in name or name == '..':
            raise ValueError('Invalid path: {}'.format(name))
        return name

    def _get_path(self, msg):
        path = []
        if 'root' in msg:
            if msg.get('type') == 'file':
                if self._honor_single_file_root:
                    path = msg['root']
            else:
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

            if 'root' in msg:
                if self._honor_single_file_root:
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
            else:
                self._current_file = open(filepath, 'wb')

            if self._verbose:
                self._verbose('{}'.format(filepath))


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
            if self._error:
                self._error('Error: {}/{}'.format(msg['exception'], msg['data']))

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
                if self._verbose:
                    self._verbose('{} - {}'.format(msg['data'], msg['exception']))

        elif msgtype == 'dirview':
            dirview = msg['data']
            self._current_file_dir = self._get_path(dirview)
            self._current_file_dir_raw = os.path.sep.join(dirview['root'])

            if not self._archive:
                if not self._download_dir:
                    self._download_dir = self._local_path

                self._last_directory = os.path.join(
                    self._download_dir, self._current_file_dir)

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
                    with open(os.path.join(self._last_directory, self._check_name(z)), 'wb'):
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

                    lnk = list(x for x in lnk if x)
                    symto = os.path.sep.join(lnk)

                    if self.client.is_windows():
                        if symto.startswith(os.path.sep) or ':' in symto:
                            symto = os.path.relpath(
                                symto.upper(),
                                start=self._current_file_dir_raw.upper()
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
        if self._completed.is_set():
            return

        try:
            if self._terminate:
                self._terminate()

                self._completed.wait(5)

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
