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

from junctions import readlink, lstat

try:
    from ntfs_streams import get_streams

    def has_xattrs(path):
        try:
            return get_streams(path)
        except (OSError, IOError, WindowsError):
            return None

except ImportError:
    def has_xattrs(path):
        return None

try:
    from pupwinutils.security import getfileowner, sidbyname

    def uidgid(path, item, as_text=True):
        try:
            owner, group = getfileowner(path, as_sid=not as_text)
            return owner[0], group[0]
        except (OSError, IOError, WindowsError):
            return '?', '?'

    def username_to_uid(username):
        try:
            sid = sidbyname(username)
            if not sid:
                raise NoSuchUser(username)

        except WindowsError:
            raise NoSuchUser(username)

    def groupname_to_gid(groupname):
        try:
            sid = sidbyname(groupname)
            if not sid:
                raise NoSuchUser(groupname)

        except WindowsError:
            raise NoSuchGroup(groupname)

except ImportError:
    def uidgid(path, item):
        return '', ''

    def username_to_uid(username):
        raise NoSuchUser(username)

    def groupname_to_gid(groupname):
        raise NoSuchGroup(groupname)
