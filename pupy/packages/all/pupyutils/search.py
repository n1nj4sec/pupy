#!/usr/bin/env python
# -*- coding: utf-8 -*-

from scandir import scandir
if scandir is None:
    from scandir import scandir_generic as scandir

import os
import re
import sys

try:
    import mmap
except ImportError:
    pass

import threading
import rpyc

import errno

class Search(object):
    def __init__(self, path,
                     strings=[], max_size=20000000, root_path='.', no_content=False,
                     case=False, binary=False, follow_symlinks=False, terminate=None):
        self.max_size = int(max_size)
        self.follow_symlinks = follow_symlinks
        self.no_content = no_content
        self.binary = binary
        self.case = case

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
            re.compile(string, i) for string in strings
        ]

        self.terminate = terminate

        if root_path == '.':
            self.root_path = os.getcwdu()
        else:
            self.root_path = root_path

    def search_string(self, path, size):
        try:
            with open(path, 'rb') as f:
                m = mmap.mmap(f.fileno(), size, access=mmap.ACCESS_READ)
                try:
                    if not self.binary:
                        sample_size = min(size, 4096)
                        sample = m[:sample_size]
                        sample_zeros = len([x for x in sample if ord(x) == '\x00'])
                        if sample_zeros not in (0, sample_size/2):
                            return

                    for string in self.strings:
                        for match in string.finditer(m):
                            yield match.group()
                finally:
                    m.close()

        except Exception, e:
            yield e

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
                    if not self.strings or not (self.strings and entry.is_file()):
                        if not any_file:
                            yield entry.path
                    else:
                        size = entry.stat().st_size
                        if size > self.max_size:
                            continue

                        for string in self.search_string(entry.path, min(size, self.max_size)):
                            if string:
                                if self.no_content:
                                    yield entry.path
                                    break
                                else:
                                    yield (entry.path, string)

                if entry.is_dir(follow_symlinks=followlinks):
                    for res in self.scanwalk(entry.path):
                        yield res

        # try / except used for permission denied
        except Exception, e:
            yield e

    def run(self):
        if os.path.isfile(self.root_path):
            for res in self.search_string(self.root_path):
                try:
                    yield u'{} > {}'.format(self.root_path, res)
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
                            on_error('Scanwalk exception: {}:{}'.format(
                                str(type(result)), str(result)))
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
