# -*- coding: utf-8 -*-
import os
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

from scandir import scandir
if scandir is None:
    from scandir import scandir_generic as scandir

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

textchars = bytearray({7,8,9,10,12,13,27} | set(range(0x20, 0x100)) - {0x7f})

from fsutils import (
    readlink, lstat, has_xattrs, uidgid
)

def is_binary(text):
    return bool(text.translate(None, textchars))

def file_timestamp(entry):
    try:
        d = datetime.fromtimestamp(entry.stat().st_mtime)
        return str(d.strftime("%d/%m/%y"))
    except:
        return '00/00/00'

def try_unicode(path):
    if type(path) != unicode:
        try:
            return path.decode('utf-8')
        except UnicodeDecodeError:
            pass

    return path

class FakeStat(object):
    st_mode = 0b100000
    st_uid = -1
    st_gid = -1
    st_size = -1
    st_mtime = 0

def safe_stat(path):
    path = try_unicode(path)
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
    path = try_unicode(path)
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
    path = try_unicode(path)

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
            T_MODE: 0666,
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
    path = try_unicode(path)

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
        path = try_unicode(path)
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
    cwd = os.getcwdu()
    path, results = _complete(cwd, path, limit, dirs)

    if path.endswith(('/', '\\')):
        path = path[:-1]

    if path and cwd not in ('/', '\\'):
        relpath = os.path.relpath(path, start=cwd)
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

def ls(path=None, listdir=True, limit=4096, list_arc=False, resolve_uidgid=False):
    if path:
        path = try_unicode(path)
        path = os.path.expanduser(path)
        path = os.path.expandvars(path)
    else:
        path = os.getcwdu()

    results = []
    found = False

    for path in glob.iglob(path):
        if not os.path.exists(path):
            raise IOError('The path does not exist')

        found = True

        if os.path.isdir(path):
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

    cwd = os.getcwdu()

    if path:
        path = try_unicode(path)
        path = os.path.expanduser(path)
        path = os.path.expandvars(path)
    else:
        path = os.path.expanduser("~")
        path = try_unicode(path)

    try:
        os.chdir(path)
        PREV_CWD = cwd
    except OSError:
        if path == '-' and PREV_CWD is not None:
            os.chdir(PREV_CWD)
            PREV_CWD = cwd
        else:
            raise

# -------------------------- For mkdir function --------------------------

def mkdir(directory):
    directory = try_unicode(directory)

    directory = os.path.expanduser(directory)
    directory = os.path.expandvars(directory)

    os.makedirs(directory)

# -------------------------- For cp function --------------------------

def cp(src, dst):
    dst = try_unicode(dst)
    dst = os.path.expanduser(dst)
    dst = os.path.expandvars(dst)

    found = False

    src = try_unicode(src)
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

            if os.path.isdir(src):
                shutil.copytree(src, real_dst)
            else:
                shutil.copyfile(src, real_dst)
        else:
            raise ValueError('The file {} does not exist'.format(src))

    if not found:
        raise ValueError('The file {} does not exist'.format(src))


# -------------------------- For mv function --------------------------

def mv(src, dst):
    dst = try_unicode(dst)
    dst = os.path.expanduser(dst)
    dst = os.path.expandvars(dst)

    found = False

    src = try_unicode(src)
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

            shutil.move(src, real_dst)

    if not found:
        raise ValueError('The file/directory does not exist')


# -------------------------- For mv function --------------------------

def rm(path):
    path = try_unicode(path)
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
                except OSError, e:
                    exception = e
        else:
            raise ValueError("File/directory does not exists")

    if not files:
        raise ValueError("File/directory does not exists")

    if files == 1 and exception:
        raise exception

# -------------------------- For cat function --------------------------

def cat(path, N, n, grep, encoding=None):
    if grep:
        grep = re.compile(grep)

    path = try_unicode(path)
    path = os.path.expanduser(path)
    path = os.path.expandvars(path)

    found = False

    data = []

    for path in glob.iglob(path):
        if os.path.exists(path):
            found = True
            if os.path.isfile(path):
                with open(path, 'r') as fin:
                    bom = fin.read(2)
                    need_newline = True
                    if bom == codecs.BOM_UTF16_LE:
                        fin = codecs.EncodedFile(fin, 'utf-8', 'utf-16-le')
                    elif bom == codecs.BOM_UTF16_BE:
                        fin = codecs.EncodedFile(fin, 'utf-8', 'utf-16-be')
                    elif bom == codecs.BOM_UTF32_LE:
                        fin = codecs.EncodedFile(fin, 'utf-8', 'utf-32-le')
                    elif bom == codecs.BOM_UTF32_BE:
                        fin = codecs.EncodedFile(fin, 'utf-8', 'utf-32-be')
                    elif encoding is not None:
                        fin = codecs.EncodedFile(fin, 'utf-8', encoding)
                        fin.seek(0)
                        need_newline = False
                    else:
                        need_newline = False
                        fin.seek(0)

                    if need_newline:
                        fin.readline()

                    if N:
                        data += tail(fin, N, grep)
                    elif grep or n:
                        for line in fin:
                            line = line.rstrip('\n')
                            if not grep or grep.search(line):
                                data.append(line)
                            if n and len(data) >= n:
                                break
                    else:
                        fin.seek(0, os.SEEK_END)
                        file_size = fin.tell()
                        fin.seek(0)
                        block_size = 4*8192
                        block = fin.read(block_size)
                        if file_size > block_size:
                            block += "\n[FILE TRUNCATED, USE DOWNLOAD]"
                        return block
            else:
                raise ValueError('Not a file')
        else:
            raise ValueError('File does not exists')

    if not found:
        raise ValueError('File does not exists')

    return '\n'.join(data)

def tail(f, n, grep):
    if n <= 0:
        raise ValueError('Invalid amount of lines: {}'.format(n))

    BUFSIZ = 4096
    CR = '\n'
    data = ''

    f.seek(0, os.SEEK_END)

    fsize = f.tell()
    block = -1
    exit = False

    retval = []

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

        if len(retval) + data.count(CR) >= n:
            if grep:
                lines = data.splitlines()
                llines = len(lines)
                for idx in xrange(llines-1):
                    line = lines[llines-idx-1]

                    if grep.search(line):
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

    if len(retval) < n:
        n -= len(retval)
        retval += data.splitlines()[-n:]

    return retval

# ------------------------------- For edit  -------------------------------

def fgetcontent(path, max_size=1*1024*1024):
    path = try_unicode(path)
    path = os.path.expanduser(path)
    path = os.path.expandvars(path)

    with open(path, 'rb') as f:
        content = f.read(max_size)
        if f.read(1):
            raise ValueError('File is too big')

        return content

def fputcontent(path, content, append=False):
    path = try_unicode(path)
    path = os.path.expanduser(path)
    path = os.path.expandvars(path)

    ftime = None

    try:
        s = os.stat(path)
        ftime = (s.st_atime, s.st_mtime)
    except OSError, e:
        if e.errno == errno.EEXIST and not append:
            pass

    with open(path, 'ab' if append else 'wb') as f:
        f.write(content)

    if ftime:
        os.utime(path, ftime)

# ----------------------------- For datetime  -----------------------------

def now():
    return str(datetime.datetime.now())

# -------------------------- For getuid function --------------------------

def getuid():
    return getpass.getuser()

# --------------------------------- For RFS -------------------------------

def dlstat(path):
    path = try_unicode(path)
    pstat = os.stat(path)
    return {
        k:getattr(pstat, k) for k in dir(pstat) if not k.startswith('__')
    }

def dstatvfs(path):
    path = try_unicode(path)
    pstat = os.statvfs(path)
    return {
        k:getattr(pstat, k) for k in dir(pstat) if not k.startswith('__')
    }
