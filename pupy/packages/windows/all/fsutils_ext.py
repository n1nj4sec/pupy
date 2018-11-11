# -*- coding: utf-8 -*-

from pupwinutils.security import getfileowneracls
from fsutils import has_xattrs
from os import stat, path
from junctions import islink, readlink
from pupyutils.basic_cmds import mode_to_letter

def getfilesec(filepath):

    header = ''

    if path.isfile(filepath):
        try:
            with open(filepath) as fileobj:
                header = fileobj.read(4096)
        except IOError:
            pass

    filestat = stat(filepath)
    owner, group, acls = getfileowneracls(filepath)
    streams = has_xattrs(filepath)
    link = None

    try:
        if islink(filepath):
            link = readlink(filepath)
    except (WindowsError, ValueError, OSError, IOError):
        pass

    mode = mode_to_letter(filestat.st_mode)

    extras = {
        'ACLs': [unicode(x) for x in acls] if acls else None,
        'Streams': streams,
        'Link': link
    }

    return int(filestat.st_ctime), int(filestat.st_atime), \
      int(filestat.st_mtime), filestat.st_size, owner, group, \
      header, mode, {k:v for k,v in extras.iteritems() if v}
