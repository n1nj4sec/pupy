# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import os
import sys
import glob
import shutil
import getpass
import stat
import datetime
import re
import codecs
import errno

from zipfile import ZipFile, is_zipfile
from tarfile import is_tarfile
from tarfile import open as open_tarfile

from gzip import GzipFile

from scandir import scandir

if scandir is None:
    from scandir import scandir_generic as scandir

from network.lib.convcompat import (
    as_native_string, as_unicode_string,
    fix_exception_encoding, try_as_unicode_string,
    DEFAULT_MB_ENCODING
)


if sys.version_info.major > 2:
    xrange = range
    getcwd = os.getcwd

else:
    getcwd = os.getcwdu


PREV_CWD = None

# -------------------------- For ls functions --------------------------

T_NAME      = 0
T_TYPE      = 1
T_SPEC      = 2
T_MODE      = 3
T_UID       = 4
T_GID       = 5
T_SIZE      = 6
T_TIMESTAMP = 7
T_PATH      = 8
T_FILES     = 9
T_FILE      = 10
T_TRUNCATED = 11
T_ZIPFILE   = 12
T_TARFILE   = 13
T_HAS_XATTR = 14


from fsutils import (
    readlink, lstat, has_xattrs, uidgid
)


def file_timestamp(entry):
    try:
        d = datetime.fromtimestamp(entry.stat().st_mtime)
        return str(d.strftime("%d/%m/%y"))
    except:
        return '00/00/00'


class FakeStat(object):
    st_mode = 0b100000
    st_uid = -1
    st_gid = -1
    st_size = -1
    st_mtime = 0


def safe_stat(path):
    path = as_unicode_string(path)
    try:
        return lstat(path)
    except:
        pass

    try:
        return os.stat(path)
    except:
        pass

    return FakeStat()


def safe_listdir(path):
    path = as_unicode_string(path)
    try:
        return os.listdir(path)
    except:
        return []


def mode_to_letter(mode):
    if stat.S_ISDIR(mode):
        return 'D'
    elif stat.S_ISLNK(mode):
        return 'L'
    elif stat.S_ISBLK(mode):
        return 'B'
    elif stat.S_ISCHR(mode):
        return 'C'
    elif stat.S_ISFIFO(mode):
        return 'F'
    elif stat.S_ISSOCK(mode):
        return 'S'
    else:
        return ''


def special_to_letter(mode):
    letter = ''

    ALL_R = (stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    ALL_W = (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)

    if mode & stat.S_ISGID:
        letter += 'G'
    if mode & stat.S_ISUID:
        letter += 'U'
    if mode & stat.S_ISVTX:
        letter += 'T'
    if mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
        letter += 'E'
    if (mode & ALL_R) == ALL_R:
        letter += 'R'
    if (mode & ALL_W) == ALL_W:
        letter += 'W'

    return letter


def _stat_to_ls_struct(path, name, _stat, resolve_uidgid=False):
    if stat.S_ISLNK(_stat.st_mode):
        try:
            name += ' -> '+readlink(path)
        except:
            pass

    try:
        f_xattrs = has_xattrs(path)
    except (OSError, IOError):
        f_xattrs = False

    if resolve_uidgid:
        uid, gid = uidgid(path, _stat)
    else:
        uid, gid = _stat.st_uid, _stat.st_gid

    return {
        T_NAME: name,
        T_TYPE: mode_to_letter(_stat.st_mode),
        T_SPEC: special_to_letter(_stat.st_mode),
        T_MODE: _stat.st_mode,
        T_UID:  uid,
        T_GID:  gid,
        T_SIZE: _stat.st_size,
        T_TIMESTAMP: int(_stat.st_mtime),
        T_HAS_XATTR: bool(f_xattrs)
    }


def _invalid_ls_struct(path, name):
    return {
        T_NAME: name,
        T_TYPE: '?',
        T_SPEC: '?',
        T_MODE: 0,
        T_UID:  0,
        T_GID:  0,
        T_SIZE: 0,
        T_TIMESTAMP: 0,
        T_HAS_XATTR: False,
    }


def list_file(path, resolve_uidgid=False):
    path = as_unicode_string(path)

    if path.endswith(os.path.sep):
        name = os.path.dirname(
            os.path.basename(path)
        )
    else:
        name = os.path.basename(path)

    _stat = safe_stat(path)
    return _stat_to_ls_struct(path, name, _stat, resolve_uidgid)


def list_tar(path, max_files=None):
    result = []
    for idx, item in enumerate(open_tarfile(path, 'r:*')):
        if idx >= max_files:
            result.append({
                T_TRUNCATED: 0,
                T_TYPE: 'X',
            })

            break

        name = item.name

        letter = ''
        if item.islnk():
            name = name + ' => ' + item.linkname
            letter = 'L'
        elif item.issym():
            name = name + ' -> ' + item.linkname
            letter = 'L'
        elif item.isdir():
            letter = 'D'
        elif item.isfifo():
            letter = 'F'
        elif item.isblk():
            letter = 'B'
        elif item.ischr():
            letter = 'C'

        result.append({
            T_NAME: name,
            T_TYPE: letter,
            T_MODE: item.mode,
            T_SPEC: special_to_letter(item.mode),
            T_UID: item.uid,
            T_GID: item.gid,
            T_SIZE: item.size,
            T_TIMESTAMP: item.mtime,
            T_HAS_XATTR: False,
        })

    return result


def list_zip(path, max_files=None):
    result = []

    zts = datetime.datetime.fromtimestamp(0)

    for idx, item in enumerate(ZipFile(path).infolist()):
        if idx >= max_files:
            result.append({
                T_TRUNCATED: 0,
                T_TYPE: 'X',
            })

            break

        result.append({
            T_NAME: item.filename,
            T_TYPE: '', # TODO - support flags
            T_SPEC: '', # TODO - support flags
            T_MODE: 0o666,
            T_UID: 0,
            T_GID: 0,
            T_SIZE: item.file_size,
            T_TIMESTAMP: (
                datetime.datetime(*item.date_time) - zts
            ).total_seconds(),
            T_HAS_XATTR: False,
        })

    return result


def list_dir(path, max_files=None, resolve_uidgid=False):
    path = as_unicode_string(path)

    result = []

    filescnt = 0
    truncated = None

    items = scandir(path)

    try:
        for item in items:
            try:
                result.append(_stat_to_ls_struct(
                    item.path, item.name,
                    item.stat(follow_symlinks=False),
                    resolve_uidgid=resolve_uidgid))
            except OSError:
                result.append(_invalid_ls_struct(item.path, item.name))

            filescnt += 1
            if max_files and filescnt >= max_files:
                truncated = 0
                break

    except StopIteration:
        pass

    if truncated is not None:
        try:
            for item in items:
                truncated += 1

        except StopIteration:
            pass

        if truncated:
            result.append({
                T_TRUNCATED: truncated,
                T_TYPE: 'X',
            })

    return result


def _complete(cwd, path, limit=32, dirs=None):
    if path:
        path = as_unicode_string(path)
        path = os.path.expanduser(path)
        path = os.path.expandvars(path)
    else:
        path = cwd + '/'

    results = []
    part = ''

    path = path.replace('\\', '/').replace('//', '/')
    if path.endswith('/') and os.path.isdir(path):
        pass

    elif os.path.exists(path):
        return path, ['']

    else:
        part = os.path.basename(path)
        path = os.path.dirname(path)
        if not path:
            path = cwd
        elif not os.path.isdir(path):
            return '', []

    for item in scandir(path):
        if item.name.startswith(part):
            if dirs is None or \
                (dirs is True and item.is_dir()) or \
                (dirs is False and not item.is_dir()):
                results.append(item.name)
        if len(results) > limit:
            break

    return path, results


def complete(path, limit=32, dirs=None):
    cwd = getcwd()
    path, results = _complete(cwd, path, limit, dirs)

    if path.endswith(('/', '\\')):
        path = path[:-1]

    if path and cwd not in ('/', '\\'):
        try:
            relpath = os.path.relpath(path, start=cwd)
        except ValueError:
            relpath = os.path.relpath(path, start='/')
        if not relpath.startswith('..'):
            path = relpath

    if path.startswith(('./', '.\\')):
        path = path[2:]
    elif path == '.':
        path = None

    return path, results


def safe_is_zipfile(filepath):
    try:
        return is_zipfile(filepath)
    except (OSError, IOError):
        return False


def safe_is_tarfile(filepath):
    try:
        return is_tarfile(filepath)
    except (OSError, IOError):
        return False


def env(*args):
    if args:
        if len(args) == 1:
            key = as_native_string(args[0])
            return as_unicode_string(os.environ.get(key))

        key, value = args

        key = as_native_string(key)
        if value is None:
            del os.environ[key]
            return

        os.environ[key] = as_native_string(value)
        return

    values = []

    for key, value in os.environ.items():
        values.append((
            as_unicode_string(key),
            as_unicode_string(value)
        ))

    return tuple(values)


def ls(
    path=None, listdir=True, limit=4096,
        list_arc=False, resolve_uidgid=False):

    if path:
        path = as_unicode_string(path)
        path = os.path.expanduser(path)
        path = os.path.expandvars(path)
    else:
        path = getcwd()

    results = []
    found = False

    for path in glob.iglob(path):
        if not os.path.exists(path):
            raise IOError('The path does not exist')

        found = True

        if os.path.isdir(path):
            try:
                if listdir:
                    results.append({
                        T_PATH: path,
                        T_FILES: list_dir(
                            path, max_files=limit,
                            resolve_uidgid=resolve_uidgid)
                    })
                else:
                    results.append({
                        T_PATH: path,
                        T_FILE: list_file(path, resolve_uidgid)
                    })
            except Exception as e:
                fix_exception_encoding(e)
                raise

        elif os.path.isfile(path):
            if safe_is_zipfile(path):
                if list_arc:
                    results.append({
                        T_ZIPFILE: path,
                        T_FILES: list_zip(path, max_files=limit)
                    })
                else:
                    results.append({
                        T_ZIPFILE: path,
                        T_FILE: list_file(path)
                    })
            elif safe_is_tarfile(path):
                if list_arc:
                    results.append({
                        T_TARFILE: path,
                        T_FILES: list_tar(path, max_files=limit)
                    })
                else:
                    results.append({
                        T_TARFILE: path,
                        T_FILE: list_file(path)
                    })
            else:
                results.append({
                    T_PATH: path,
                    T_FILE: list_file(path, resolve_uidgid)
                })
        else:
            results.append({
                T_PATH: path,
                T_FILE: list_file(path, resolve_uidgid)
            })

    if not found:
        raise ValueError('The file/path does not exist')

    return results

# -------------------------- For cd function --------------------------


def cd(path=None):
    global PREV_CWD

    cwd = getcwd()

    if path:
        path = as_unicode_string(path)
        path = os.path.expanduser(path)
        path = os.path.expandvars(path)
    else:
        path = os.path.expanduser("~")
        path = as_unicode_string(path)

    try:
        os.chdir(path)
        PREV_CWD = cwd
    except OSError as exc:
        if path == '-' and PREV_CWD is not None:
            os.chdir(PREV_CWD)
            PREV_CWD = cwd
        else:
            fix_exception_encoding(exc)
            raise

# -------------------------- For mkdir function --------------------------


def mkdir(directory):
    directory = as_unicode_string(directory)

    directory = os.path.expanduser(directory)
    directory = os.path.expandvars(directory)

    try:
        os.makedirs(directory)
    except OSError as exc:
        fix_exception_encoding(exc)
        raise

# -------------------------- For cp function --------------------------


def cp(src, dst):
    dst = as_unicode_string(dst)
    dst = os.path.expanduser(dst)
    dst = os.path.expandvars(dst)

    found = False

    src = as_unicode_string(src)
    src = os.path.expanduser(src)
    src = os.path.expandvars(src)

    for src in glob.iglob(src):
        if os.path.exists(src):
            found = True

            if os.path.isdir(dst):
                real_dst = os.path.join(dst, os.path.basename(src))
            else:
                real_dst = dst

            if os.path.exists(real_dst):
                raise ValueError('{} already exists'.format(real_dst))

            try:
                if os.path.isdir(src):
                    shutil.copytree(src, real_dst)
                else:
                    shutil.copyfile(src, real_dst)
            except Exception as e:
                fix_exception_encoding(e)
                raise
        else:
            raise ValueError('The file {} does not exist'.format(src))

    if not found:
        raise ValueError('The file {} does not exist'.format(src))


# -------------------------- For mv function --------------------------


def mv(src, dst):
    dst = as_unicode_string(dst)
    dst = os.path.expanduser(dst)
    dst = os.path.expandvars(dst)

    found = False

    src = as_unicode_string(src)
    src = os.path.expanduser(src)
    src = os.path.expandvars(src)

    for src in glob.iglob(src):
        if os.path.exists(src):
            found = True

            if os.path.isdir(dst):
                real_dst = os.path.join(dst, os.path.basename(src))
            else:
                real_dst = dst

            if os.path.exists(real_dst):
                raise ValueError('File/directory already exists')

            try:
                shutil.move(src, real_dst)
            except Exception as e:
                fix_exception_encoding(e)
                raise

    if not found:
        raise ValueError('The file/directory does not exist')


# -------------------------- For mv function --------------------------


def rm(path):
    path = as_unicode_string(path)
    path = os.path.expanduser(path)
    path = os.path.expandvars(path)

    files = 0
    exception = None

    for path in glob.iglob(path):
        if os.path.exists(path):
            files += 1
            if os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=True)
            else:
                try:
                    os.remove(path)
                except OSError as e:
                    exception = e
        else:
            raise ValueError("File/directory does not exists")

    if not files:
        raise ValueError("File/directory does not exists")

    if files == 1 and exception:
        fix_exception_encoding(exception)
        raise

# -------------------------- For cat function --------------------------


def _cat(data, dups, fin, N, n, grep, encoding=None, filter_out=False):
    bom = fin.read(2)
    need_newline = True

    decoded = True

    if bom == codecs.BOM_UTF16_LE:
        fin = codecs.getreader('utf-16-le')(fin)
    elif bom == codecs.BOM_UTF16_BE:
        fin = codecs.getreader('utf-16-be')(fin)
    elif bom == codecs.BOM_UTF32_LE:
        fin = codecs.getreader('utf-32-le')(fin)
    elif bom == codecs.BOM_UTF32_BE:
        fin = codecs.getreader('utf-32-be')(fin)
    elif bom == b'\x1f\x8b':
        if N:
            raise ValueError('Tail is not supported for GZip files')
        fin.seek(0)
        fin = GzipFile(mode='r', fileobj=fin)
    elif encoding is not None:
        fin = codecs.getreader(encoding)(fin)
        fin.seek(0)
        need_newline = False
    else:
        need_newline = False
        decoded = False
        fin.seek(0)

    if need_newline:
        fin.readline()

    if decoded:
        newline = '\n'
        record_dm = '\t'
        truncate = '[FILE TRUNCATED, USE DOWNLOAD]'

        if grep:
            grep = re.compile(as_unicode_string(grep))

    else:
        newline = b'\n'
        record_dm = b'\t'
        truncate = b''

        if grep:
            if isinstance(grep, bytes):
                pass
            else:
                grep = grep.encode(DEFAULT_MB_ENCODING)

            grep = re.compile(grep)

    if N:
        data.extend(
            tail(fin, N, grep, filter_out, decoded)
        )

    elif grep or n:
        for line in fin:
            line = line.rstrip(newline)
            matches = None
            if grep:
                matches = grep.search(line)
            if not grep or (not filter_out and matches) or \
                    (filter_out and not matches):
                if matches:
                    groups = matches.groups()
                    if groups:
                        record = record_dm.join(groups)
                        if record not in dups:
                            data.append(record)
                            dups.add(record)
                    else:
                        data.append(line)
                else:
                    data.append(line)

            if n and len(data) >= n:
                break
    else:
        block_size = 4*8192
        block = fin.read(block_size)

        if len(block) == block_size:
            block += truncate

        try:
            block = try_as_unicode_string(block)
        except UnicodeError:
            pass

        data.append(block)


def cat(path, N, n, grep, encoding=None, filter_out=False):
    path = as_unicode_string(path)
    path = os.path.expanduser(path)
    path = os.path.expandvars(path)

    found = False

    data = []
    dups = set()

    for path in glob.iglob(path):
        if not os.path.exists(path):
            continue

        found = True
        if not os.path.isfile(path):
            raise ValueError('Not a file')

        with open(path, 'rb') as fin:
            try:
                _cat(data, dups, fin, N, n, grep, encoding, filter_out)
            except Exception as e:
                fix_exception_encoding(e)
                raise

    if not found:
        raise ValueError('File does not exists')

    return tuple(data)


def tail(f, n, grep, filter_out=False, decoded=True):
    if n <= 0:
        raise ValueError('Invalid amount of lines: {}'.format(n))

    BUFSIZ = 4096

    if decoded:
        newline = '\n'
        record_dm = '\t'
        data = ''
    else:
        newline = b'\n'
        record_dm = b'\t'
        data = b''

    f.seek(0, os.SEEK_END)

    fsize = f.tell()
    block = -1
    exit = False

    retval = []
    dups = set()

    while not exit:
        step = (block * BUFSIZ)

        if abs(step) >= fsize:
            f.seek(0)
            newdata = f.read(BUFSIZ - (abs(step) - fsize))
            exit = True
        else:
            f.seek(step, os.SEEK_END)
            newdata = f.read(BUFSIZ)

        data = newdata + data

        if (len(retval) + data.count(newline) >= n) or exit:
            if grep:
                lines = data.splitlines()
                llines = len(lines)
                to_process = llines if exit else lines - 1
                for idx in xrange(to_process):
                    line = lines[llines-idx-1]

                    matches = grep.search(line)

                    if (not filter_out and matches) or \
                       (filter_out and not matches):
                        if matches:
                            groups = matches.groups()
                            if groups:
                                record = record_dm.join(groups)
                                if record not in dups:
                                    retval.insert(0, record)
                                    dups.add(record)
                            else:
                                retval.insert(0, line)
                        else:
                            retval.insert(0, line)

                    if len(retval) >= n:
                        break

                if len(retval) >= n:
                    break
                else:
                    data = lines[0]
                    block -= 1
            else:
                break
        else:
            block -= 1

    if len(retval) < n and not grep:
        n -= len(retval)
        retval.append(
            data.splitlines()[-n:]
        )

    return retval

# ------------------------------- For edit  -------------------------------


def fgetcontent(path, max_size=1*1024*1024):
    path = as_unicode_string(path)
    path = os.path.expanduser(path)
    path = os.path.expandvars(path)

    with open(path, 'rb') as f:
        content = f.read(max_size)
        if f.read(1):
            raise ValueError('File is too big')

        return content


def fputcontent(path, content, append=False):
    path = as_unicode_string(path)
    path = os.path.expanduser(path)
    path = os.path.expandvars(path)

    if not isinstance(content, bytes):
        content = content.encode(DEFAULT_MB_ENCODING)

    ftime = None

    try:
        s = os.stat(path)
        ftime = (s.st_atime, s.st_mtime)
    except OSError as e:
        if e.errno == errno.EEXIST and not append:
            pass

    with open(path, 'ab' if append else 'wb') as f:
        if content:
            f.write(content)

    if ftime:
        os.utime(path, ftime)

# ----------------------------- For datetime  -----------------------------


def now():
    return as_unicode_string(str(datetime.datetime.now()))

# -------------------------- For getuid function --------------------------


def getuid():
    return as_unicode_string(getpass.getuser())

# --------------------------------- For RFS -------------------------------


def dlstat(path):
    path = as_unicode_string(path)

    try:
        pstat = os.stat(path)
    except OSError as e:
        fix_exception_encoding(e)
        raise

    return {
        k: getattr(pstat, k) for k in dir(pstat) if not k.startswith('__')
    }


def dstatvfs(path):
    path = as_unicode_string(path)
    try:
        pstat = os.statvfs(path)
    except OSError as e:
        fix_exception_encoding(e)
        raise

    return {
        k: getattr(pstat, k) for k in dir(pstat) if not k.startswith('__')
    }
