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

from fsutils import uidgid, username_to_uid, groupname_to_gid, has_xattrs

PERMISSION_ERRORS = [
    getattr(errno, x) for x in ('EPERM', 'EACCESS') if hasattr(errno, x)
]

SEARCH_WINDOW_SIZE = 32768

from uuid import uuid4

OWAW_PROBE_NAME = str(uuid4())

class Search(object):
    def __init__(
        self, path,
        strings=[], max_size=20000000, root_path='.', no_content=False,
        case=False, binary=False, follow_symlinks=False, terminate=None,
        same_fs=True, search_in_archives=False, content_only=False,
        suid=False, sgid=False, user=False, group=False,
        owaw=False, newer=None, older=None, xattr=False
    ):

        self.max_size = int(max_size)
        self.follow_symlinks = follow_symlinks
        self.no_content = no_content
        self.binary = binary
        self.case = case
        self.same_fs = same_fs
        self.search_in_archives = search_in_archives
        self.content_only = content_only if strings else False

        self.suid = suid
        self.sgid = sgid
        self.user = username_to_uid(user) if user else None
        self.group = groupname_to_gid(group) if group else None
        self.owaw = owaw
        self.newer = newer
        self.older = older
        self.xattr = xattr

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

        if self.xattr and self.xattr is not True:
            self.xattr = re.compile(self.xattr, i)

        self.terminate = terminate

        if root_path == '.':
            self.root_path = os.getcwdu()
        else:
            self.root_path = root_path

        if self.same_fs:
            self.same_fs = os.stat(self.root_path).st_dev

        self.extended = any([
            self.xattr, self.suid, self.sgid,
            self.user, self.group, self.owaw,
            self.newer, self.older
        ])

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

    def filter_extended(self, item):
        if not self.extended:
            return True

        path = item.path

        if self.xattr:
            if self.xattr is True:
                if has_xattrs(path):
                    return True
            elif any([self.xattr.match(x) for x in has_xattrs(path)]):
                return True

        if self.suid or self.sgid and sys.platform != 'win32':
            if self.suid and item.stat().st_mode & 0o4000:
                return True

            if self.sgid and item.stat().st_mode & 0o2000:
                return True

        if self.user or self.group:
            uid, gid = uidgid(path, item.stat(), as_text=False)
            if self.user and self.user == uid or self.group and self.group == gid:
                return True

        if self.owaw:
            if item.is_dir():
                try:
                    tmp_file = os.path.join(path, OWAW_PROBE_NAME)
                    f = open(tmp_file, 'w')
                    f.close()
                    os.unlink(tmp_file)
                    return True

                except (OSError, IOError):
                    pass

            elif item.is_file():
                try:
                    f = open(path, 'a')
                    f.close()
                    return True

                except (OSError, IOError):
                    pass

        if self.newer and item.stat().st_mtime > self.newer:
            return True

        if self.older and item.stat().st_mtime < self.older:
            return True

        return False

    def search_in_archive(self, path):
        any_file = not self.name or self.path

        # We don't support extended search in archives

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

                        try:
                            archive_filename = item.filename.decode(sys.getfilesystemencoding())
                        except UnicodeDecodeError:
                            archive_filename = item.filename

                        if self.strings:
                            for match in self.search_string_in_fileobj(
                                zf.open(item), filename='zip:'+path+':'+item.filename):
                                yield ('zip:'+path+':'+archive_filename, match)

                        elif not any_file:
                            yield u'zip:'+path+u':'+archive_filename
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

                        try:
                            archive_filename = item.name.decode(sys.getfilesystemencoding())
                        except UnicodeDecodeError:
                            archive_filename = item.name

                        if self.strings and item.isfile():
                            for match in self.search_string_in_fileobj(
                                tf.extractfile(item), filename='tar:+'+archive_filename+':'+path):

                                yield ('tar:'+path+':'+archive_filename, match)

                        elif not any_file:
                            yield u'tar:'+path+u':'+archive_filename

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
                    (self.name and self.name.match(entry.name)) or \
                    (self.path and self.path.match(entry.path)) or \
                    any_file
                ):
                    try:
                        if not self.strings or not (self.strings and entry.is_file()):
                            if not any_file and self.filter_extended(entry):
                                yield entry.path
                        else:
                            size = entry.stat().st_size
                            if size > self.max_size:
                                continue

                            if not self.filter_extended(entry):
                                continue

                            for s in self.search_string(entry.path):
                                if s:
                                    if isinstance(s, Exception):
                                        yield s

                                    elif self.no_content:
                                        if self.filter_extended(entry):
                                            yield entry.path
                                            break

                                    else:
                                        if self.filter_extended(entry):
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
                    yield (self.root_path, res)
                except:
                    pass

            if self.search_in_archives:
                for res in self.search_in_archive(self.root_path):
                    if self.content_only and type(res) is not tuple:
                        continue

                    try:
                        yield res
                    except:
                        pass

        else:
            for files in self.scanwalk(self.root_path, followlinks=self.follow_symlinks):
                if self.content_only and type(files) is not tuple:
                    continue

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
