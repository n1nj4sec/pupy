#!/usr/bin/env python
# -*- coding: utf-8 -*-

from scandir import scandir
if scandir is None:
    from scandir import scandir_generic as scandir

import os
import re
import sys

import threading
import rpyc

import errno
import traceback

import string

from zipfile import ZipFile, is_zipfile
from tarfile import is_tarfile
from tarfile import open as open_tarfile

PERMISSION_ERRORS = [
    getattr(errno, x) for x in ('EPERM', 'EACCESS') if hasattr(errno, x)
]

SEARCH_WINDOW_SIZE = 32768

class Search(object):
    def __init__(
        self, path,
        strings=[], max_size=20000000, root_path='.', no_content=False,
        case=False, binary=False, follow_symlinks=False, terminate=None,
        same_fs=True, search_in_archives=False
    ):

        self.max_size = int(max_size)
        self.follow_symlinks = follow_symlinks
        self.no_content = no_content
        self.binary = binary
        self.case = case
        self.same_fs = same_fs
        self.search_in_archives = search_in_archives

        if self.case:
            i = re.IGNORECASE | re.UNICODE
        else:
            i = re.UNICODE

        if type(path) != unicode:
            path = path.decode(sys.getfilesystemencoding())

        if type(root_path) != unicode:
            root_path = root_path.decode(sys.getfilesystemencoding())

        path = os.path.expandvars(os.path.expanduser(path))

        if os.path.isdir(path):
            root_path = path
            self.name = None
            self.path = None
        elif path.startswith('/'):
            root_path = os.path.dirname(path)
            self.name = re.compile(os.path.basename(path), i)
            self.path = None
        elif '/' in path:
            self.path = re.compile(path, i)
            self.name = None
        else:
            self.name = re.compile(path, i)
            self.path = None

        self.strings = [
            re.compile(s, i) for s in strings
        ]

        self.terminate = terminate

        if root_path == '.':
            self.root_path = os.getcwdu()
        else:
            self.root_path = root_path

        if self.same_fs:
            self.same_fs = os.stat(self.root_path).st_dev

    def search_string_in_fileobj(self, fileobj, find_all=False, filename=None):
        try:
            offset = 0
            prev = ''
            found = False

            while offset < self.max_size and not found and not (
                self.terminate and self.terminate.is_set()):

                chunk = fileobj.read(SEARCH_WINDOW_SIZE)

                if not self.binary:
                    for x in chunk:
                        if x not in string.printable:
                            return

                for s in self.strings:
                    for match in s.finditer(prev + chunk):
                        yield match.group()

                        if not find_all:
                            found = True
                            break

                    if found:
                        break

                if not chunk:
                    break

                prev = chunk
                offset += len(chunk)

        except IOError, e:
            if e.errno in PERMISSION_ERRORS:
                return

        except Exception, e:
            setattr(e, 'filename', filename)
            setattr(e, 'exc', (sys.exc_type, sys.exc_value, sys.exc_traceback))
            yield e

    def search_string(self, path, find_all=False):
        try:
            with open(path, 'rb') as f:
                for result in self.search_string_in_fileobj(f, find_all, filename=path):
                    yield result

        except IOError, e:
            if e.errno in PERMISSION_ERRORS:
                return

        except Exception, e:
            setattr(e, 'filename', path)
            setattr(e, 'exc', (sys.exc_type, sys.exc_value, sys.exc_traceback))
            yield e

    def search_in_archive(self, path):
        any_file = not self.name or self.path

        if is_zipfile(path):
            zf = ZipFile(path)
            try:
                for item in zf.infolist():
                    if self.terminate and self.terminate.is_set():
                        break

                    name = os.path.basename(item.filename)

                    if (self.name and self.name.match(name)) or \
                      (self.path and self.path.match(item.filename)) or \
                      any_file:
                        if self.strings:
                            for match in self.search_string_in_fileobj(
                                zf.open(item), filename='zip:'+path+':'+item.filename):
                                yield ('zip:'+path+':'+item.filename, match)
                        elif not any_file:
                            yield 'zip:'+path+':'+item.filename
            finally:
                zf.close()

        elif is_tarfile(path):
            tf = open_tarfile(path, 'r:*')
            try:
                for item in tf:
                    if self.terminate and self.terminate.is_set():
                        break

                    name = os.path.basename(item.name)
                    if (self.name and self.name.match(name)) or \
                      (self.path and self.path.match(item.name)) or \
                      any_file:

                        if self.strings and item.isfile():
                            for match in self.search_string_in_fileobj(
                                tf.extractfile(item), filename='tar:+'+item.name+':'+path):

                                yield ('tar:'+path+':'+item.name, match)

                        elif not any_file:
                            yield 'tar:'+path+':'+item.name

            except:
                import traceback
                traceback.print_exc()

            finally:
                tf.close()


    def scanwalk(self, path, followlinks=False):

        ''' lists of DirEntries instead of lists of strings '''

        try:
            for entry in scandir(path):
                if self.terminate and self.terminate.is_set():
                    break

                any_file = not self.name or self.path

                if (
                    (self.name and self.name.match(entry.name)) or
                    (self.path and self.path.match(entry.path)) or
                    any_file
                ):
                    try:
                        if not self.strings or not (self.strings and entry.is_file()):
                            if not any_file:
                                yield entry.path
                        else:
                            size = entry.stat().st_size
                            if size > self.max_size:
                                continue

                            for s in self.search_string(entry.path):
                                if s:
                                    if isinstance(s, Exception):
                                        yield s

                                    elif self.no_content:
                                        yield entry.path
                                        break

                                    else:
                                        yield (entry.path, s)
                    except IOError, e:
                        if e.errno in PERMISSION_ERRORS:
                            continue

                    except Exception, e:
                        setattr(e, 'filename', entry.path)
                        setattr(e, 'exc', (sys.exc_type, sys.exc_value, sys.exc_traceback))

                try:
                    if entry.is_dir(follow_symlinks=followlinks):
                        if not self.same_fs or self.same_fs == entry.stat().st_dev:
                            for res in self.scanwalk(entry.path):
                                yield res

                    elif self.search_in_archives and entry.is_file():
                        for res in self.search_in_archive(entry.path):
                            yield res

                except IOError, e:
                    if e.errno in PERMISSION_ERRORS:
                        continue

                except Exception, e:
                    setattr(e, 'filename', entry.path)
                    setattr(e, 'exc', (sys.exc_type, sys.exc_value, sys.exc_traceback))

        except IOError, e:
            if e.errno in PERMISSION_ERRORS:
                return

        # try / except used for permission denied
        except Exception, e:
            setattr(e, 'filename', path)
            setattr(e, 'exc', (sys.exc_type, sys.exc_value, sys.exc_traceback))
            yield e

    def run(self):
        if os.path.isfile(self.root_path):
            for res in self.search_string(self.root_path, find_all=True):
                try:
                    yield u'{} > {}'.format(self.root_path, res)
                except:
                    pass

            if self.search_in_archives:
                for res in self.search_in_archive(self.root_path):
                    try:
                        yield u'{} @ {}'.format(self.root_path, res)
                    except:
                        pass

        else:
            for files in self.scanwalk(self.root_path, followlinks=self.follow_symlinks):
                yield files

    def _run_thread(self, on_data, on_completed, on_error):
        previous_result = None

        for result in self.run():
            if isinstance(result, Exception):
                if on_error:
                    if isinstance(result, OSError):
                        if result.errno not in (errno.EPERM, errno.EACCES):
                            on_error(
                                result.filename + ': ' + \
                                u' '.join(x for x in result.args if type(x) in (str, unicode)))
                    elif isinstance(result, UnicodeDecodeError):
                        on_error('Invalid encoding: {}'.format(repr(result.args[1])))
                    else:
                        try:
                            on_error('Scanwalk exception: {}:{}:{}'.format(
                                str(type(result)), str(result),
                                '\n'.join(traceback.format_exception(*result.exc))))
                        except Exception, e:
                            try:
                                on_error('Scanwalk exception (module): ({})'.format(e))
                            except:
                                pass
                            break

                continue

            try:
                if result != previous_result:
                    on_data(result)
                    previous_result = result
            except Exception, e:
                try:
                    on_error('Scanwalk exception (module): {}'.format(e))
                except:
                    pass

                break

        on_completed()

    def stop(self):
        if self.terminate:
            self.terminate.set()

    def run_cb(self, on_data, on_completed, on_error=None):
        if not self.terminate:
            self.terminate = threading.Event()

        on_completed = rpyc.async(on_completed)

        search = threading.Thread(target=self._run_thread, args=(on_data, on_completed, on_error))
        search.daemon = False
        search.start()

    def run_cbs(self, on_data, on_completed, on_error=None):
        if not self.terminate:
            self.terminate = threading.Event()

        search = threading.Thread(target=self._run_thread, args=(on_data, on_completed, on_error))
        search.daemon = False
        search.start()
