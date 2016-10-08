# -*- coding: UTF8 -*-
import os
from datetime import datetime
import shutil

# -------------------------- For ls functions --------------------------

def sizeof_fmt(num, suffix='B'):
    try:
        num = int(num)
        for unit in ['','Ki','Mi','Gi','Ti','Pi','Ei','Zi']:
            if abs(num) < 1024.0:
                return "%3.1f %s%s" % (num, unit, suffix)
            num /= 1024.0
        return "%.1f %s%s" % (num, 'Yi', suffix)
    except:
        return '0.00 B'

def list_file(real_name, path):
    category = '      '
    if os.path.isdir(path):
        category = '<REP> '

    try:
        d = datetime.fromtimestamp(os.path.getmtime(path))
        date = str(d.strftime("%d/%m/%y"))
    except:
        date = '00/00/00'
    
    try:
        size = sizeof_fmt(os.path.getsize(path))
        s = str(size)
        while len(s) < 10:
            s = s + ' '
    except:
        s =  '          '

    return ' ' + date + '  ' + category + '  ' + s + '  ' + real_name + '\n'

def list_dir(path):
    output = ''
    try:
        ff = ""
        for f in os.listdir(path):
            ff += list_file(f, path + os.sep + f)
    except:
        ff = '\n[-] You need more permission to show the content of the file'
    
    return ff
    
def ls(path=None):
    if not path:
        path = "."
    
    if not os.path.exists(path):
        raise IOError("The path \"%s\" does not exist" % path)

    if os.path.isdir(path):
        allfiles = list_dir(path)
    elif os.path.isfile(path):
        allfiles = list_file(path, os.getcwd() + os.sep + path)
    
    return "%s" % allfiles
    
# -------------------------- For cd function --------------------------

def cd(path=None):
    if not path:
        home = os.path.expanduser("~")
        os.chdir(home)
        return
    
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
