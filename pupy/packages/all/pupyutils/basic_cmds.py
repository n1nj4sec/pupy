# -*- coding: utf-8 -*-
import datetime
import os
import glob
import shutil
import getpass
import stat

# -------------------------- For ls functions --------------------------

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

def try_unicode(path):
    if type(path) != unicode:
        try:
            return path.decode('utf-8')
        except UnicodeDecodeError:
            pass

    return path

def safe_stat(path):
    path = try_unicode(path)
    try:
        return os.lstat(path)
    except:
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
    elif stat.S_ISBLK(mode):
        return 'B'
    elif stat.S_ISCHR(mode):
        return 'C'
    elif stat.S_ISFIFO(mode):
        return 'F'
    elif stat.S_ISSOCK(mode):
        return 'S'
    elif stat.S_ISLNK(mode):
        return 'L'
    else:
        return ''

def special_to_letter(mode):
    l = ''

    ALL_R = (stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    ALL_W = (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)

    if mode & stat.S_ISGID:
        l += 'G'
    if mode & stat.S_ISUID:
        l += 'U'
    if mode & stat.S_ISVTX:
        l += 'T'
    if mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
        l += 'E'
    if ( mode & ALL_R ) == ALL_R:
        l += 'R'
    if ( mode & ALL_W ) == ALL_W:
        l += 'W'

    return l

def list_file(path):
    path = try_unicode(path)

    _stat = safe_stat(path)
    if path.endswith(os.path.sep):
        name = os.path.dirname(
            os.path.basename(path)
        )
    else:
        name = os.path.basename(path)

    if stat.S_ISLNK(_stat.st_mode):
        try:
            name += ' -> '+os.readlink(path)
        except:
            pass

    return {
        'name': name,
        'type': mode_to_letter(_stat.st_mode),
        'spec': special_to_letter(_stat.st_mode),
        'mode': _stat.st_mode,
        'uid':  _stat.st_uid,
        'gid':  _stat.st_gid,
        'size': _stat.st_size,
        'ts': int(_stat.st_mtime),
    }

def list_dir(path):
    path = try_unicode(path)

    return [
        list_file(os.path.join(path, x)) for x in safe_listdir(path)
    ]

def ls(path=None,listdir=True):
    if path:
        path = try_unicode(path)
        path = os.path.expanduser(path)
        path = os.path.expandvars(path)
    else:
        path = os.getcwd()

    results = []
    found = False

    for path in glob.iglob(path):

        if not os.path.exists(path):
            raise IOError("The path \"%s\" does not exist" % path)

        found = True

        if os.path.isdir(path):
            if listdir:
                results.append({
                    'path': path,
                    'files': list_dir(path)
                })
            else:
                results.append({
                    'path': path,
                    'file': list_file(path)
                })

        elif os.path.isfile(path):
            results.append({
                'path': path,
                'file': list_file(path)
            })


    if not found:
        raise ValueError("The file \"%s\" does not exist" % path)

    return results

# -------------------------- For cd function --------------------------

def cd(path=None):
    if path:
        path = try_unicode(path)
        path = os.path.expanduser(path)
        path = os.path.expandvars(path)
    else:
        home = os.path.expanduser("~")
        try:
            os.chdir(home)
            return
        except:
            return "[-] Home directory not found (or access denied): %s" % home

    if os.path.isdir(path):
        try:
            os.chdir(path)
        except:
            return "[-] Permission denied to change to this directory"

    else:
        return "[-] \"%s\" is not a repository" % path

# -------------------------- For mkdir function --------------------------

def mkdir(directory):
    directory = try_unicode(directory)

    directory = os.path.expanduser(directory)
    directory = os.path.expandvars(directory)

    if not os.path.exists(directory):
        os.makedirs(directory)
    else:
        return "[-] The directory \"%s\" already exists" % directory

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
                raise ValueError('{} already exists'.format(real_dst))

            shutil.move(src, real_dst)

    if not found:
        raise ValueError('The file {} does not exist'.format(src))


# -------------------------- For mv function --------------------------

def rm(path):
    path = try_unicode(path)
    path = os.path.expanduser(path)
    path = os.path.expandvars(path)

    found = False

    for path in glob.iglob(path):
        if os.path.exists(path):
            found = True
            if os.path.isdir(path):
                shutil.rmtree(path)
            else:
                os.remove(path)
        else:
            return "[-] The directory \"%s\" does not exists" % path

    if not found:
        return "[-] The directory \"%s\" does not exists" % path

# -------------------------- For cat function --------------------------

def cat(path):
    path = try_unicode(path)
    path = os.path.expanduser(path)
    path = os.path.expandvars(path)

    found = False

    data = ''

    for path in glob.iglob(path):
        if os.path.exists(path):
            found = True
            if not os.path.isdir(path):
                # not open files too big (< 7 Mo)
                if os.path.getsize(path) < 7000000:
                    with open(path, 'r') as fin:
                        data += fin.read()
                else:
                    return "[-] \"%s\" is too big to be openned (max size: 7 Mo)" % path
            else:
                return "[-] \"%s\" is a directory" % path

        else:
            return "[-] The file \"%s\" does not exists" % path

    if not found:
        return "[-] The file \"%s\" does not exists" % path

    return data


# -------------------------- For getuid function --------------------------

def getuid():
    return getpass.getuser()
