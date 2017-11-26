# -*- coding: utf-8 -*-

import os
import zipfile

def try_unicode(path):
    if type(path) != unicode:
        try:
            return path.decode('utf-8')
        except UnicodeDecodeError:
            pass

    return path

def zip(src, dst):
    src = try_unicode(src)

    if not os.path.exists(src):
        return False, "The file \"%s\" does not exists" % src

    isDir = False
    if os.path.isdir(src):
        isDir = True

    if not dst:
        if isDir:
            d = src.split(os.sep)
            dst = d[len(d)-1] + '.zip'
        else:
            dst = src + '.zip'

    dst = try_unicode(dst)

    # To not overwrite an existing file
    if os.path.exists(dst):
        return False, "The destination file \"%s\" already exists" % dst

    # Zip process
    zf = zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED)
    if isDir:
        abs_src = os.path.abspath(src)
        for dirname, subdirs, files in os.walk(src):
            for filename in files:
                absname = os.path.abspath(os.path.join(dirname, filename))
                arcname = absname[len(abs_src) + 1:]
                zf.write(absname, arcname)
    else:
        zf.write(src)

    zf.close()
    return True, "File zipped correctly: \"%s\"" % dst


def unzip(src, dst):
    src = try_unicode(src)

    if not os.path.exists(src):
        return False, "The file \"%s\" does not exists" % src

    if not dst:
        d = src.split(os.sep)
        dst = d[len(d)-1].replace('.zip', '')

    dst = try_unicode(dst)

    # To not overwrite an existing file
    if os.path.exists(dst):
        return False, "The destination file \"%s\" already exists" % dst

    if zipfile.is_zipfile(src):
        with zipfile.ZipFile(src, "r") as z:
            z.extractall(dst)
        return True, "File unzipped correctly: \"%s\"" % dst
    else:
        return False, 'The zipped file does not have a valid zip format: \"%s\"' % src


def list(src):
    src = try_unicode(src)
    if not os.path.exists(src):
        return False, "The file \"%s\" does not exists" % src

    if zipfile.is_zipfile(src):
        with zipfile.ZipFile(src, "r") as z:
            return True, [
                (
                    i.filename, i.file_size,
                ) for i in z.infolist()
            ]
    else:
        return False, 'The zipped file does not have a valid zip format: \"%s\"' % src
