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

from os import readlink, lstat, path
from sys import platform

HAVE_XATTRS = False

if platform.startswith('linux'):
    from struct import unpack_from, unpack

    try:
        from xattr import listxattr, getxattr
        from prctl import ALL_CAPS, ALL_CAP_NAMES
        from posix1e import ACL

        def has_xattrs(filepath):
            return listxattr(filepath)

        def getacls(filepath):
            acls = ''

            try:
                acls += ACL(file=filepath).to_any_text()
            except (OSError, IOError):
                pass

            if path.isdir(filepath):
                try:
                    defaults = ACL(filedef=filepath).to_any_text()
                    if defaults:
                        defaults = '\n'.join([
                            'default:' + x for x in defaults.split('\n')
                        ])
                        acls += '\n' + defaults
                except (OSError, IOError):
                    pass

            return acls

        def getcaps(filepath):
            try:
                bincap = getxattr(filepath, 'security.capability')
            except (IOError, OSError):
                return None

            version, = unpack_from('<I', bincap)
            revision = (version  & 0xFF000000) >> 24

            caps = bincap[4:]
            if not (revision == 1 and len(caps) == 8 or
                    revision == 2 and len(caps) == 16):
                raise ValueError('Invalid caps payload')

            effective = version & 1

            MAX_CAP = 32
            permitted = [unpack('<I', caps[0:4])[0]]
            inheritable = [unpack('<I', caps[4:8])[0]]

            if version == 2:
                MAX_CAP = 64
                permitted.append(unpack('<I', caps[8:12])[0])
                inheritable.append(unpack('<I', caps[12:16])[0])

            permitted_flags = []
            inheritable_flags = []
            for x in xrange(min(len(ALL_CAP_NAMES), MAX_CAP)):
                idx = ((x) >> 5)
                mask = (1 << ((x) & 31))

                if permitted[idx] & mask:
                    permitted_flags.append(ALL_CAP_NAMES[ALL_CAPS.index(x)])

                if inheritable[idx] & mask:
                    inheritable_flags.append(ALL_CAP_NAMES[ALL_CAPS.index(x)])

            return permitted_flags, inheritable_flags, bool(effective)

        HAVE_XATTRS = True

    except ImportError:
        pass

if not HAVE_XATTRS:
    def has_xattrs(filepath):
        return None

    def getcaps(filepath):
        return None

    def getacls(filepath):
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

    def uidgid(filepath, item, as_text=True):
        if not as_text:
            return item.st_uid, item.st_gid

        pw = getpwuid(item.st_uid)
        gr = getgrgid(item.st_gid)

        return \
          pw.pw_name if pw else str(item.st_uid), \
          gr.gr_name if gr else str(item.st_gid)

except ImportError:
    def uidgid(filepath, item):
        return item.st_uid, item.st_gid

    def username_to_uid(username):
        raise NoSuchUser(username)

    def groupname_to_gid(groupname):
        raise NoSuchGroup(groupname)
