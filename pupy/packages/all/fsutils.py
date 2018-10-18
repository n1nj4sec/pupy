# -*- coding: utf-8 -*-

__all__ = (
    'readlink', 'lstat', 'has_xattrs', 'uidgid',
    'username_to_uid', 'groupname_to_gid',
    'NoUidGidMapping', 'NoSuchUser', 'NoSuchGroup'
)

class NoUidGidMapping(Exception):
    pass

class NoSuchUser(NoUidGidMapping):
    pass

class NoSuchGroup(NoUidGidMapping):
    pass

from os import readlink, lstat

try:
    from xattr import listxattr

    def has_xattrs(path):
        return listxattr(path)

except ImportError:
    def has_xattrs(path):
        return None

try:
    from pwd import getpwuid, getpwnam
    from grp import getgrgid, getgrnam

    def username_to_uid(username):
        try:
            return getpwnam(username).pw_uid
        except KeyError:
            raise NoSuchUser(username)

    def groupname_to_gid(groupname):
        try:
            return getgrnam(groupname).gr_gid
        except KeyError:
            raise NoSuchGroup(groupname)

    def uidgid(path, item, as_text=True):
        if not as_text:
            return item.st_uid, item.st_gid

        pw = getpwuid(item.st_uid)
        gr = getgrgid(item.st_gid)

        return \
          pw.pw_name if pw else str(item.st_uid), \
          gr.gr_name if gr else str(item.st_gid)

except ImportError:
    def uidgid(path, item):
        return item.st_uid, item.st_gid

    def username_to_uid(username):
        raise NoSuchUser(username)

    def groupname_to_gid(groupname):
        raise NoSuchGroup(groupname)
