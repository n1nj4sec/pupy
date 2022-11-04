# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

__all__ = (
    'readlink', 'lstat', 'has_xattrs', 'uidgid',
    'username_to_uid', 'groupname_to_gid',
    'NoUidGidMapping', 'NoSuchUser', 'NoSuchGroup'
)


from os import readlink, lstat
from sys import platform

from pupy.network.lib.convcompat import as_unicode_string


def _has_xattrs(filepath):
    return None


has_xattrs = _has_xattrs

if platform.startswith('linux'):

    try:
        from xattr import listxattr

        def linux_has_xattrs(filepath):
            return listxattr(filepath)

        has_xattrs = linux_has_xattrs

    except ImportError:
        pass


class NoUidGidMapping(Exception):
    pass


class NoSuchUser(NoUidGidMapping):
    pass


class NoSuchGroup(NoUidGidMapping):
    pass


try:
    from pwd import getpwuid, getpwnam
    from grp import getgrgid, getgrnam

    def username_to_uid(username):
        try:
            return as_unicode_string(
                getpwnam(username).pw_uid
            )
        except KeyError:
            raise NoSuchUser(username)

    def groupname_to_gid(groupname):
        try:
            return as_unicode_string(
                getgrnam(groupname).gr_gid
            )
        except KeyError:
            raise NoSuchGroup(groupname)

    def uidgid(filepath, item, as_text=True):
        if not as_text:
            return item.st_uid, item.st_gid

        try:
            pw = getpwuid(item.st_uid)
        except KeyError:
            pw = None

        try:
            gr = getgrgid(item.st_gid)
        except KeyError:
            gr = None

        return as_unicode_string(
            pw.pw_name
        ) if pw else as_unicode_string(
            str(item.st_uid)
        ), as_unicode_string(
            gr.gr_name
        ) if gr else as_unicode_string(
            str(item.st_gid)
        )

except ImportError:
    def uidgid(filepath, item):
        return item.st_uid, item.st_gid

    def username_to_uid(username):
        raise NoSuchUser(username)

    def groupname_to_gid(groupname):
        raise NoSuchGroup(groupname)
