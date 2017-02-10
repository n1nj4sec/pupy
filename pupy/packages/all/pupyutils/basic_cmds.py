# -*- coding: UTF8 -*-
import os
from datetime import datetime
import shutil
import getpass

# -------------------------- For ls functions --------------------------

def size_human_readable(num, suffix='B'):
    try:
        num = int(num)
        for unit in ['','Ki','Mi','Gi','Ti','Pi','Ei','Zi']:
            if abs(num) < 1024.0:
                return "%3.1f %s%s" % (num, unit, suffix)
            num /= 1024.0
        return "%.1f %s%s" % (num, 'Yi', suffix)
    except:
        return '0.00 B'

def file_timestamp(path):
    try:
        d = datetime.fromtimestamp(os.path.getmtime(path))
        return str(d.strftime("%d/%m/%y"))
    except:
        return '00/00/00'

def output_format(file):
    return u'  {}{}{}{}\n'.format(
                   '{:<10}'.format(file['timestamp']), 
                   '{:<7}'.format(file['isDir']),
                   '{:<10}'.format(file['size']), 
                   '{:<40}'.format(file['name']),
            )

def list_file(path):
    file = {'isDir': '', 'name': '', 'size': 'N/A', 'timestamp': ''}
    file['size'] = size_human_readable(os.path.getsize(path))
    file['name'] = path.split(os.sep)[-1]
    file['timestamp'] = file_timestamp(path)
    return output_format(file)

def list_dir(path, followlinks=False):
    # import this lib only for this function
    from scandir import scandir

    results = ''
    try:
        for entry in scandir(path):
            file = {'isDir': '', 'name': '', 'size': 'N/A', 'timestamp': ''}
            
            if entry.is_dir(follow_symlinks=followlinks):
                file['isDir'] = '<REP>'
            
            file['size'] = size_human_readable(entry.stat(follow_symlinks=False).st_size)
            file['name'] = entry.name
            file['timestamp'] = file_timestamp(os.path.join(path, entry.name))
            results += output_format(file)
    except:
        pass
    return results
    
def ls(path=None):
    if not path:
        path = os.getcwd()
    
    if not os.path.exists(path):
        raise IOError("The path \"%s\" does not exist" % path)

    if os.path.isdir(path):
        current_path = 'Listing files from %s' % path
        return current_path, list_dir(path)

    elif os.path.isfile(path):
        current_path = 'File: %s' % path
        return current_path, list_file(path)
    
# -------------------------- For cd function --------------------------

def cd(path=None):
    if not path:
        home = os.path.expanduser("~")
        try:
            os.chdir(home)
            return
        except:
            return "[-] Home directory not found (or access denied): %s" % home
    
    path = os.path.join(os.getcwd(), path)
    if os.path.isdir(path):
        try:
            os.chdir(path)
        except:
            return "[-] Permission denied to change to this directory"
            
    else:
        return "[-] \"%s\" is not a repository" % path

# -------------------------- For mkdir function --------------------------

def mkdir(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)
    else:
        return "[-] The directory \"%s\" already exists" % directory

# -------------------------- For cp function --------------------------

def cp(src, dst):
    if dst.endswith('.'):
        d = src.split(os.sep)
        dst = os.path.abspath(os.path.join(dst, d[len(d)-1]))

    if not os.path.exists(dst):
        if os.path.exists(src):
            if os.path.isdir(src):
                shutil.copytree(src, dst)
            else:
                shutil.copyfile(src, dst)
        else:
            return "[-] The file \"%s\" does not exist" % src
    else:
        return "[-] The file \"%s\" already exists" % dst

# -------------------------- For mv function --------------------------

def mv(src, dst):
    if dst.endswith('.'):
        d = src.split(os.sep)
        dst = os.path.abspath(os.path.join(dst, d[len(d)-1]))

    if not os.path.exists(dst):
        if os.path.exists(src):
                shutil.move(src, dst)
        else:
            return "[-] The file \"%s\" does not exist" % src
    else:
        return "[-] The file \"%s\" already exists" % dst

# -------------------------- For mv function --------------------------

def rm(path):
    if os.path.exists(path):
        if os.path.isdir(path):
            shutil.rmtree(path)
        else:
            os.remove(path)
    else:
        return "[-] The directory \"%s\" does not exists" % path

# -------------------------- For cat function --------------------------

def cat(path):
    if os.path.exists(path):
        if not os.path.isdir(path):
            # not open files too big (< 7 Mo)
            if os.path.getsize(path) < 7000000:
                f = open(path, 'r')
                d=f.read()
                f.close()
                return d
            else:
                return "[-] \"%s\" is too big to be openned (max size: 7 Mo)" % path
        else:
            return "[-] \"%s\" is a directory" % path
                    
    else:
        return "[-] The file \"%s\" does not exists" % path


# -------------------------- For getuid function --------------------------

def getuid():
    return getpass.getuser()