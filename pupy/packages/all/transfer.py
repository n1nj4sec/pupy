# -*- coding: utf-8 -*-
from threading import Thread, Event
from Queue import Queue
from os import path, stat
from rpyc.core import brine

import sys

from network.lib.buffer import Buffer

from zipfile import ZipFile, is_zipfile
from tarfile import is_tarfile
from tarfile import open as open_tarfile

HAS_BUFFER_OPTIMIZATION = False

if Buffer in brine.simple_types:
    HAS_BUFFER_OPTIMIZATION = True
else:
    from io import BytesIO as Buffer

if sys.platform == 'win32':
    from junctions import islink, readlink, lstat
else:
    from os import readlink, lstat
    from os.path import islink

from zlib import compress

from scandir import scandir
if scandir is None:
    from scandir import scandir_generic as scandir

import rpyc
import sys
import traceback

try:
    import umsgpack as msgpack
except ImportError:
    import msgpack

import re

from network.lib import getLogger
logger = getLogger('transfer')

FIELDS_MAP = {
    x:y for x,y in enumerate([
        'st_mtime', 'st_gid', 'st_uid', 'st_mode', 'st_rdev'
    ])
}

FIELDS_MAP_ENCODE = {
    y:x for x,y in FIELDS_MAP.iteritems()
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

def decodepath(filepath):
    try:
        return filepath.decode('utf-8')
    except:
        return filepath

class Transfer(object):
    def __init__(self, exclude=None, include=None, follow_symlinks=False,
                 find_size=False, ignore_size=False, single_device=False,
                     chunk_size=1*1024*1024):
        self.initialized = False

        self._terminate = Event()
        self.worker = Thread(target=self._worker_run)
        self.queue = Queue()

        self.follow_symlinks = follow_symlinks
        self.chunk_size = chunk_size
        self.find_size = find_size
        self.ignore_size = ignore_size
        self.single_device = single_device
        self.read_portion = min(16*4096, self.chunk_size)

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
            except OSError, e:
                logger.debug('_walk_scandir:topstat: %s', e)
                return

            except Exception, e:
                logger.exception('_walk_scandir:topstat: %s', e)
                raise

            if self.single_device is True:
                self.single_device = topstat.st_dev
            elif self.single_device != topstat.st_dev:
                return

        try:
            scandir_it = scandir(top)
        except OSError, e:
            logger.debug('_walk_scandir:scandir: %s', e)
            return

        except Exception, e:
            logger.exception('_walk_scandir:scandir: %s', e)
            raise

        while not self._terminate.is_set():
            try:
                try:
                    entry = next(scandir_it)

                except UnicodeDecodeError, e:
                    ## ???
                    logger.debug('_walk_scandir:next(scandir_it): %s', e)
                    continue

                except StopIteration:
                    break

            except OSError, e:
                logger.debug('_walk_scandir:next(scandir_it): %s', e)
                return

            if entry is None:
                logger.error('Entry is None')
                continue

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

            if not self.follow_symlinks:
                try:
                    is_symlink = entry.is_symlink()

                    if not is_symlink and sys.platform == 'win32' and entry.is_dir(follow_symlinks=False):
                        is_symlink = islink(entry.path)
                except OSError, e:
                    logger.debug('_walk_scandir:follow_symlinks: %s', e)
                    pass

            if not is_symlink:
                try:
                    is_dir = entry.is_dir(follow_symlinks=self.follow_symlinks)
                except OSError, e:
                    logger.debug('_walk_scandir:is_dir: %s', e)
                    pass

            if not is_dir and not is_symlink:
                try:
                    is_file = entry.is_file(follow_symlinks=self.follow_symlinks)
                except OSError, e:
                    logger.debug('_walk_scandir:is_file: %s', e)
                    pass

            if not is_dir and not is_file and not is_symlink:
                try:
                    is_symlink = entry.is_symlink()
                except:
                    pass

            if is_symlink:
                try:
                    linked_to = readlink(name)
                    symlinks.append((entry, linked_to))
                except (IOError, OSError):
                    pass

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
                            dups[inode] = name

                    if not hardlinked:
                        files.append(entry)

                except OSError, e:
                    logger.debug('_walk_scandir:hardlinked: %s', e)
            else:
                special.append(entry)

        yield top, dirs, files, symlinks, hardlinks, special

        dirpaths = [
            edir.name for edir in dirs
        ]

        del dirs[:], files[:], symlinks[:], hardlinks[:], special[:]

        for direntry in dirpaths:
            new_path = path.join(top, direntry)
            if self.follow_symlinks or not islink(new_path):
                for dentry in self._walk_scandir(new_path, dups):
                    yield dentry

    def _worker_run_unsafe(self, buf):
        global HAS_BUFFER_OPTIMIZATION

        while not self._terminate.is_set():
            task = self.queue.get()

            if task is None:
                self._terminate.set()
                break

            command, args, callback = task
            if command is None and args is None:
                if callback is not None:
                    callback(None, None)

                self._terminate.set()
                break

            restore_compression = False
            channel = None

            try:
                channel = object.__getattribute__(callback, "____conn__")()._channel
            except:
                pass

            try:
                for chunk in command(*args):
                    msgpack.dump(chunk, buf)

                    if channel and channel.compress and chunk.get(F_TYPE) == T_ZCONTENT:
                        restore_compression = True
                        channel.compress = False

                    del chunk

                    bpos = None

                    if HAS_BUFFER_OPTIMIZATION:
                        bpos = len(buf)
                    else:
                        bpos = buf.tell()

                    if bpos > self.chunk_size:
                        if HAS_BUFFER_OPTIMIZATION:
                            callback(buf, None)
                            buf.drain()
                        else:
                            buf.seek(0)
                            data = buf.read(bpos)
                            buf.seek(0)
                            callback(data, None)
                            del data

                        if restore_compression:
                            try:
                                channel.compress = restore_compression
                            except:
                                pass

                            restore_compression = False

                    if self._terminate.is_set():
                        break

                bpos = None
                if HAS_BUFFER_OPTIMIZATION:
                    bpos = len(buf)
                else:
                    bpos = buf.tell()

                if bpos > 0:
                    if HAS_BUFFER_OPTIMIZATION:
                        callback(buf, None)
                        buf.drain()
                    else:
                        buf.seek(0)
                        data = buf.read(bpos)
                        buf.seek(0)
                        callback(data, None)
                        del data

            except Exception, e:
                try:
                    callback(None, e)
                except EOFError:
                    pass

            finally:
                if restore_compression:
                    try:
                        channel.compress = restore_compression
                    except:
                        pass

        if callback:
            callback(None, None)

    def _worker_run(self):
        try:
            buf = Buffer()
            self._worker_run_unsafe(buf)
        finally:
            del buf

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
                F_TYPE: T_SIZE,
                F_PATH: filepath,
                F_FILES: 1,
                F_SIZE: filestat.st_size,
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
            F_TYPE: T_SIZE,
            F_PATH: filepath,
            F_FILES: files_count,
            F_SIZE: files_size,
        }

    def _stat_to_vec(self, stat):
        vec = [0]*len(FIELDS_MAP_ENCODE)
        for field in dir(stat):
            if field not in FIELDS_MAP_ENCODE:
                continue

            vec[FIELDS_MAP_ENCODE[field]] = getattr(stat, field)

        return vec

    def _pack_fileobj(self, infile):
        high_entropy_cases = 0
        zeros = 0

        self._current_file = infile
        while not self._terminate.is_set():
            portion = infile.read(self.read_portion)

            if not portion:
                break

            if zeros < (0xFFFFFFFE - self.read_portion) and all(v == '\0' for v in portion):
                zeros += len(portion)
                del portion
                continue

            if zeros > 0:
                yield {
                    F_TYPE: T_SPARSE,
                    F_DATA: zeros,
                }
                zeros = 0

            zdata = None

            if high_entropy_cases < 3:
                zdata = compress(portion)

            datalen = len(portion)

            if not zdata or len(zdata) >= datalen - (datalen*0.2):
                high_entropy_cases += 1

                result = {
                    F_TYPE: T_CONTENT,
                    F_DATA: portion
                }

                del zdata, portion
                yield result

            else:
                high_entropy_cases = 0

                result = {
                    F_TYPE: T_ZCONTENT,
                    F_DATA: zdata
                }
                del zdata, portion
                yield result

        if zeros > 0:
            yield {
                F_TYPE: T_SPARSE,
                F_DATA: zeros,
            }
            zeros = 0

        yield {
            F_TYPE: T_CLOSE,
        }

    def _pack_file(self, filepath, top=None):
        yield {
            F_TYPE: T_FILE,
            F_PATH: filepath,
        }

        if top:
            filepath = path.join(top, filepath)

        if self._current_file:
            raise ValueError('Invalid messages order')

        try:
            with open(filepath, 'rb', 0) as infile:
                for portion in self._pack_fileobj(infile):
                    yield portion

        except (OSError, IOError), e:
            yield {
                F_TYPE: T_C_EXC,
                F_EXC: e.args[1],
                F_DATA: e.filename,
            }

        except Exception, e:
            yield {
                F_TYPE: T_C_EXC,
                F_EXC: str(type(e)),
                F_DATA: str(e)
            }

        finally:
            self._current_file = None

    def _pack_path(self, filepath):
        stats = []
        dirview = {
            F_TYPE: T_DIRVIEW,
            F_DATA: {
                D_ROOT: '',
                D_DIRS: [],
                D_SYMS: [],
                D_HARDS: [],
                D_SPECIALS: [],
                D_EMPTY: [],
                D_FILES: [],
            }
        }

        for root, dirs, files, syms, hards, specials in self._walk_scandir(filepath):
            for f in files:
                stats.append((f.name, f.stat()))

            dirview[F_DATA][D_ROOT] = root

            for x in dirs:
                dirview[F_DATA][D_DIRS].append((x.name, self._stat_to_vec(x.stat())))

            for x,link in syms:
                dirview[F_DATA][D_SYMS].append((x.name, link))

            for x,link in hards:
                dirview[F_DATA][D_HARDS].append((x.name, self._stat_to_vec(x.stat()), link))

            for x in dirs:
                dirview[F_DATA][D_SPECIALS].append((x.name, self._stat_to_vec(x.stat())))

            for x,y in stats:
                if not self.ignore_size or y.st_size == 0:
                    dirview[F_DATA][D_EMPTY].append((x, self._stat_to_vec(y)))
                else:
                    dirview[F_DATA][D_FILES].append((x, self._stat_to_vec(y)))

            del files[:], syms[:], hards[:], specials[:]

            yield dirview

            for k in (D_DIRS, D_SYMS, D_HARDS, D_SPECIALS, D_EMPTY, D_FILES):
                del dirview[F_DATA][k][:]

            for fp, fpstat in stats:
                if not self.ignore_size and not fpstat.st_size:
                    continue

                for portion in self._pack_file(fp, top=root):
                    yield portion
                    del portion

            del stats[:]

    def _is_supported_archive(self, filepath):
        if not filepath.startswith(('zip:', 'tar:')):
            return False

        parts = filepath.split(':', 2)
        if not len(parts) == 3:
            return False

        ext, archive_path, sub_path = parts

        if path.isfile(archive_path) and not path.isfile(filepath):
            if is_zipfile(archive_path):
                return 'zip', archive_path, sub_path
            elif is_tarfile(archive_path):
                return 'tar', archive_path, sub_path

        return False

    def _pack_any(self, filepath):
        try:
            supported_archive = self._is_supported_archive(filepath)
            if supported_archive:
                archive, archive_filepath, archive_subpath = supported_archive
                if archive == 'zip':
                    with ZipFile(archive_filepath) as zf:
                        for item in zf.infolist():
                            if item.filename == archive_subpath or \
                              item.filename.startswith(archive_subpath+'/'):

                                try:
                                    archive_filename = item.filename.decode(sys.getfilesystemencoding())
                                except UnicodeDecodeError:
                                    archive_filename = item.filename

                                yield {
                                    F_TYPE: T_FILE,
                                    F_PATH: '/'.join([
                                        archive_filepath,
                                        archive_filename
                                    ])
                                }

                                for portion in self._pack_fileobj(zf.open(item)):
                                    yield portion

                elif archive == 'tar':
                    with open_tarfile(archive_filepath) as tf:
                        for item in tf:
                            # For now support only simple files extraction, same as zip
                            if not item.isfile():
                                continue

                            if item.name == archive_subpath or \
                              item.name.startswith(archive_subpath+'/'):

                                try:
                                    archive_filename = item.name.decode(sys.getfilesystemencoding())
                                except UnicodeDecodeError:
                                    archive_filename = item.name

                                yield {
                                    F_TYPE: T_FILE,
                                    F_PATH: u'/'.join([
                                        archive_filepath,
                                        archive_filename
                                    ])
                                }

                                for portion in self._pack_fileobj(tf.extractfile(item)):
                                    yield portion

            elif path.isfile(filepath):
                root = path.dirname(filepath)
                basename = path.basename(filepath)
                portions = self._pack_file(basename, top=root)
                header = next(portions)

                if self.follow_symlinks:
                    filestat = stat(filepath)
                else:
                    filestat = lstat(filepath)

                header.update({
                    F_TYPE: T_FILE,
                    F_STAT: self._stat_to_vec(filestat),
                    F_ROOT: root,
                })

                yield header

                for portion in portions:
                    yield portion
                    del portion

            elif path.isdir(filepath):
                if self.find_size:
                    for portion in self._size(filepath):
                        yield portion
                        del portion

                for portion in self._pack_path(filepath):
                    yield portion
                    del portion
            else:
                yield {
                    F_TYPE: T_EXC,
                    F_EXC: 'No download target',
                    F_DATA: filepath
                }

                return

            yield {
                F_TYPE: T_FINISH,
                F_DATA: filepath
            }

        except Exception, e:
            yield {
                F_TYPE: T_EXC,
                F_EXC: str(type(e)),
                F_DATA: str(e) + traceback.format_exc(limit=20)
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

    def stop(self, callback):
        self.queue.put_nowait((None, None, callback))

    def terminate(self):
        if not self.initialized:
            return

        if not self._terminate.is_set():
            self._terminate.set()
            self.queue.put(None)

        try:
            self.worker.join()
        except:
            pass

    def join(self):
        self.worker.join()

def du(filepath, callback, exclude=None, include=None, follow_symlinks=False,
       single_device=False, chunk_size=1*1024*1024):
    t = Transfer(exclude, include, follow_symlinks, False, False, single_device, chunk_size)
    t.size(filepath, callback)
    t.stop(callback)
    return t.terminate

def transfer(filepath, callback, exclude=None, include=None, follow_symlinks=False,
             ignore_size=False, single_device=False, chunk_size=1*1024*1024):
    t = Transfer(exclude, include, follow_symlinks, False, ignore_size, single_device, chunk_size)
    t.transfer(filepath, callback)
    t.stop(callback)
    return t.terminate

def transfer_closure(callback, exclude=None, include=None, follow_symlinks=False,
             ignore_size=False, single_device=False, chunk_size=1*1024*1024):

    t = Transfer(exclude, include, follow_symlinks, False, ignore_size, single_device, chunk_size)

    def _closure(filespec):
        filepath = filespec
        if type(filespec) is tuple:
            filepath = filespec[0]

        t.transfer(filepath, callback)

    def _stop():
        t.stop(callback)

    return _closure, _stop, t.terminate

if __name__ == '__main__':
    import StringIO

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
    t.stop(None)
    t.join()
    print "END"
