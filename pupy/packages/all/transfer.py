# -*- coding: utf-8 -*-
from threading import Thread, Event
from Queue import Queue
from os import path, stat
import sys

if sys.platform == 'win32':
    from junctions import islink, readlink, lstat
else:
    from os import readlink, lstat
    from os.path import islink

from zlib import compress

from scandir import scandir
if scandir is None:
    from scandir import scandir_generic as scandir

from StringIO import StringIO

import errno
import rpyc
import sys

try:
    import umsgpack as msgpack
except ImportError:
    import msgpack

import re

FIELDS_MAP = {
    x:y for x,y in enumerate([
        'st_mtime', 'st_gid', 'st_uid', 'st_mode', 'st_rdev'
    ])
}

FIELDS_MAP_ENCODE = {
    y:x for x,y in FIELDS_MAP.iteritems()
}

def decodepath(filepath):
    try:
        return filepath.decode('utf-8')
    except:
        return filepath

class Transfer(object):
    def __init__(self, exclude=None, include=None, follow_symlinks=False,
                 find_size=False, ignore_size=False, single_device=False,
                     chunk_size=4*1024*1024):
        self.initialized = False

        self._terminate = Event()
        self.worker = Thread(target=self._worker_run)
        self.queue = Queue()

        self.follow_symlinks = follow_symlinks
        self.chunk_size = chunk_size
        self.find_size = find_size
        self.ignore_size = ignore_size
        self.single_device = single_device

        self.worker.daemon = True

        self.exclude = re.compile(exclude) if exclude else None
        self.include = re.compile(include) if include else None

        self.initialized = True
        self.worker.start()

        self._current_file = None

    def __del__(self):
        self.terminate()

    def _walk_scandir(self, top, dups={}):
        dirs = []
        files = []
        symlinks = []
        hardlinks = []
        special = []

        if self.single_device:
            try:
                topstat = stat(top)
            except OSError:
                return

            if self.single_device is True:
                self.single_device = topstat.st_dev
            elif self.single_device != topstat.st_dev:
                return

        try:
            scandir_it = scandir(top)
        except OSError as error:
            return

        while not self._terminate.is_set():
            try:
                try:
                    entry = next(scandir_it)

                except UnicodeDecodeError:
                    ## ???
                    continue

                except StopIteration:
                    break


            except OSError as error:
                return

            name = entry.path

            if self.exclude:
                if self.include and not self.include.match(name) and self.exclude.match(name):
                    continue
                elif self.exclude.match(name):
                    continue
            elif self.include and not self.include.match(name):
                continue

            is_dir = False
            is_file = False
            is_symlink = False
            is_special = False

            if not self.follow_symlinks:
                try:
                    is_symlink = entry.is_symlink()

                    if not is_symlink and sys.platform == 'win32' and entry.is_dir(follow_symlinks=False):
                        is_symlink = islink(entry.path)
                except OSError:
                    pass

            if not is_symlink:
                try:
                    is_dir = entry.is_dir(follow_symlinks=self.follow_symlinks)
                except OSError:
                    pass

            if not is_dir and not is_symlink:
                try:
                    is_file = entry.is_file(follow_symlinks=self.follow_symlinks)
                except OSError:
                    pass

            if not is_dir and not is_file and not is_symlink:
                try:
                    is_symlink = entry.is_symlink()
                except:
                    pass

            if is_symlink:
                try:
                    linked_to = readlink(name)
                except (IOError, OSError):
                    linked_to = ''

                symlinks.append((entry, linked_to.split(path.sep)))
            elif is_dir:
                dirs.append(entry)
            elif is_file:
                hardlinked = False
                try:
                    estat = entry.stat()
                    if estat.st_nlink > 1:
                        inode = estat.st_ino
                        if inode in dups:
                            hardlinks.append((entry, dups[inode]))
                            hardlinked = True
                        else:
                            dups[inode] = name.split(path.sep)

                    if not hardlinked:
                        files.append(entry)

                except OSError:
                    pass
            else:
                special.append(entry)

        yield top, dirs, files, symlinks, hardlinks, special

        for direntry in dirs:
            new_path = path.join(top, direntry.name)
            if self.follow_symlinks or not islink(new_path):
                for entry in self._walk_scandir(new_path, dups):
                    yield entry

    def _worker_run_unsafe(self):
        while not self._terminate.is_set():
            task = self.queue.get()
            if task is None:
                try:
                    callback(None, None)
                except:
                    pass

                self._terminate.set()
                break

            command, args, callback = task

            try:
                buf = StringIO()
                for chunk in command(*args):
                    msgpack.dump(chunk, buf)

                    del chunk

                    if buf.tell() > self.chunk_size:
                        callback(buf.getvalue(), None)

                        buf.close()
                        buf = StringIO()

                    if self._terminate.is_set():
                        break

                if buf.tell() > 0:
                    callback(buf.getvalue(), None)
                    buf.close()

            except Exception, e:
                try:
                    callback(None, e)
                except EOFError:
                    pass

            finally:
                del buf


    def _worker_run(self):
        try:
            self._worker_run_unsafe()
        finally:
            if self._current_file:
                try:
                    self._current_file.close()
                except:
                    pass

                self._current_file = None

    def _size(self, filepath):
        files_count = 0
        files_size = 0

        if not path.isdir(filepath):
            if self.follow_symlinks:
                filestat = stat(filepath)
            else:
                filestat = lstat(filepath)

            yield {
                'type': 'size',
                'path': filepath.split(path.sep),
                'files': 1,
                'size': filestat.st_size,
            }
            return

        for root, dirs, files, syms, hards, specials in self._walk_scandir(filepath):
            for f in files:
                files_count += 1
                files_size += f.stat().st_size

                if self._terminate.is_set():
                    break

            if self._terminate.is_set():
                break

        yield {
            'type': 'size',
            'path': filepath.split(path.sep),
            'files': files_count,
            'size': files_size,
        }

    def _stat_to_dict(self, stat):
        return {
            FIELDS_MAP_ENCODE.get(field):getattr(stat, field) \
            for field in dir(stat) if field in FIELDS_MAP_ENCODE
        }

    def _pack_file(self, filepath, top=None):
        yield {
            'type': 'file',
            'path': filepath.split(path.sep),
        }

        if top:
            filepath = path.join(top, filepath)

        if self._current_file:
            raise ValueError('Invalid messages order')

        try:
            info_sent = False
            high_entropy_cases = 0

            zeros = 0

            with open(filepath, 'rb') as infile:
                self._current_file = infile

                while not self._terminate.is_set():
                    portion = infile.read(self.chunk_size)

                    if not portion:
                        break

                    if all(v == '\0' for v in portion):
                        zeros += len(portion)
                        if zeros < (0xFFFFFFFE - self.chunk_size):
                            del portion
                            continue

                    if zeros > 0:
                        yield {
                            'type': 'sparse',
                            'data': zeros,
                        }
                        zeros = 0

                    zdata = None

                    if high_entropy_cases < 3:
                        zdata = compress(portion)

                    datalen = len(portion)

                    if not zdata or len(zdata) >= datalen - (datalen*0.2):
                        high_entropy_cases += 1
                        del zdata

                        yield {
                            'type': 'content',
                            'data': portion
                        }
                    else:
                        high_entropy_cases = 0
                        del portion

                        yield {
                            'type': 'zcontent',
                            'data': zdata
                        }

            if zeros > 0:
                yield {
                    'type': 'sparse',
                    'data': zeros,
                }
                zeros = 0

            yield {
                'type': 'close',
            }

        except (OSError, IOError), e:
            yield {
                'type': 'content-exception',
                'exception': e.args[1],
                'data': e.filename,
            }

        except Exception, e:
            yield {
                'type': 'content-exception',
                'exception': str(type(e)),
                'data': str(e)
            }

        finally:
            self._current_file = None

    def _pack_path(self, filepath):
        buf = b''

        for root, dirs, files, syms, hards, specials in self._walk_scandir(filepath):
            stats = {
                f.name:f.stat() for f in files
            }

            yield {
                'type': 'dirview',
                'data': {
                    'root': root.split(path.sep),
                    'dirs': {x.name: self._stat_to_dict(x.stat()) for x in dirs},
                    'syms': {x.name: link for x,link in syms},
                    'hards': {x.name: (self._stat_to_dict(x.stat()), link) for x,link in hards},
                    'specials': {x.name: self._stat_to_dict(x.stat()) for x in specials},
                    'empty': {
                        x:self._stat_to_dict(y) for x,y in stats.iteritems() \
                        if not self.ignore_size or y.st_size == 0
                    },
                    'files': {
                        x:self._stat_to_dict(y) for x,y in stats.iteritems() \
                        if self.ignore_size or y.st_size != 0
                    },
                }
            }

            for fp in sorted(stats, key=lambda x:stats[x].st_size):
                stat = stats[fp]
                if not self.ignore_size and not stat.st_size:
                    continue

                for portion in self._pack_file(fp, top=root):
                    yield portion

    def _pack_any(self, filepath):
        try:
            if path.isfile(filepath):
                root = path.dirname(filepath)
                basename = path.basename(filepath)
                portions = self._pack_file(basename, top=root)
                header = next(portions)

                if self.follow_symlinks:
                    filestat = stat(filepath)
                else:
                    filestat = lstat(filepath)

                header.update({
                    'type': 'file',
                    'stat': self._stat_to_dict(filestat),
                    'root': root.split(path.sep),
                })

                yield header

                for portion in portions:
                    yield portion

            elif path.isdir(filepath):
                if self.find_size:
                    for portion in self._size(filepath):
                        yield portion

                for portion in self._pack_path(filepath):
                    yield portion

        except Exception, e:
            yield {
                'type': 'exception',
                'exception': str(type(e)),
                'data': str(e)
            }

    def _submit_command(self, command, args, callback):
        self.queue.put((command, args, callback))

    def _expand(self, filepath):
        filepath = path.expandvars(filepath)
        filepath = path.expanduser(filepath)
        return (filepath, )

    def size(self, filepath, callback, async=False):
        filepath = decodepath(filepath)
        if async:
            callback = rpyc.async(callback)
        self._submit_command(
            self._size, self._expand(filepath), callback)

    def transfer(self, filepath, callback, async=False):
        filepath = decodepath(filepath)
        if async:
            callback = rpyc.async(callback)
        self._submit_command(
            self._pack_any, self._expand(filepath), callback)

    def stop(self):
        self.queue.put_nowait(None)

    def terminate(self):
        if not self.initialized:
            return

        if not self._terminate.is_set():
            self._terminate.set()
            self.queue.put(None)

        self.worker.join()

    def join(self):
        self.worker.join()

def du(filepath, callback, exclude=None, include=None, follow_symlinks=False,
       single_device=False, chunk_size=2*1024*1024):
    t = Transfer(exclude, include, follow_symlinks, False, False, single_device, chunk_size)
    t.size(filepath, callback)
    t.stop()
    return t.terminate

def transfer(filepath, callback, exclude=None, include=None, follow_symlinks=False,
             ignore_size=False, single_device=False, chunk_size=2*1024*1024):
    t = Transfer(exclude, include, follow_symlinks, False, ignore_size, single_device, chunk_size)
    t.transfer(filepath, callback)
    t.stop()
    return t.terminate

def transfer_closure(callback, exclude=None, include=None, follow_symlinks=False,
             ignore_size=False, single_device=False, chunk_size=2*1024*1024):

    t = Transfer(exclude, include, follow_symlinks, False, ignore_size, single_device, chunk_size)
    def _closure(filepath):
        t.transfer(filepath, callback)

    return _closure, t.stop, t.terminate

if __name__ == '__main__':
    def blob_printer(data, exception):
        if exception:
            import traceback
            print "EXCEPTION!"
            traceback.print_exc(exception)
        elif data:
            data = StringIO(data)
            print '========================================================='

            while True:
                try:
                    msg = msgpack.load(data)
                except msgpack.InsufficientDataException:
                    break

                if msg['type'].endswith('content'):
                    print "chunk size", len(msg['data'])
                elif msg['type'] == 'dirview':
                    line = msg['data']['root'] + ':'
                    for k,v in msg['data'].iteritems():
                        if k == 'root':
                            continue
                        line += ' {}:{}'.format(k, len(v))
                    print line

                else:
                    print "DATA:", msg

            print '========================================================='

    t = Transfer()
    print "START"
    t.size('/etc', callback=blob_printer, async=False)
    t.transfer('/etc', callback=blob_printer, async=False)
    print "WAIT"
    t.stop()
    t.join()
    print "END"
