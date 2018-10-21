# -*- coding: utf-8 -*-

from pupwinutils.security import getfileowneracls
from fsutils import has_xattrs
from os import stat

def getfilesec(filepath):
    filestat = stat(filepath)
    owner, group, acls = getfileowneracls(filepath)
    streams = has_xattrs(filepath)

    return int(filestat.st_ctime), int(filestat.st_atime), \
      int(filestat.st_mtime), filestat.st_size, owner, group, None, \
      '\n'.join(unicode(x) for x in acls), streams
