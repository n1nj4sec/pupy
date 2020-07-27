# -*- encoding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import sys

from io import open
from os import path, lstat, readlink
from stat import S_ISREG, S_ISLNK
from struct import unpack_from, unpack

try:
    from prctl import ALL_CAPS, ALL_CAP_NAMES
except ImportError:
    ALL_CAPS = None
    ALL_CAP_NAMES = None

from posix1e import ACL, has_extended
from xattr import getxattr
from xattr import list as list_xattrs

from pwd import getpwuid
from grp import getgrgid

from pupyutils.basic_cmds import (
    mode_to_letter, special_to_letter
)

from network.lib.convcompat import (
    as_unicode_string, try_as_unicode_string,
    fs_as_native_string, as_unicode_string_deep
)

if sys.version_info.major > 2:
    xrange = range


def getselinux(filepath):
    try:
        sectx = getxattr(filepath, 'security.selinux')
    except (IOError, OSError):
        return None

    return sectx


def getacls(filepath):
    acls = ''

    # posix1e doesn't work with unicode properly
    fs_native_filepath = fs_as_native_string(filepath)

    try:
        if not has_extended(filepath):
            return None

        acls += ACL(file=fs_native_filepath).to_any_text()
    except (OSError, IOError):
        pass

    if path.isdir(filepath):
        try:
            defaults = ACL(filedef=fs_native_filepath).to_any_text()
            if defaults:
                defaults = '\n'.join([
                    'default:' + x for x in defaults.split('\n')
                ])
                acls += '\n' + defaults
        except (OSError, IOError):
            pass

    return acls


def getcaps(filepath):
    if not ALL_CAPS and ALL_CAP_NAMES:
        return None

    try:
        bincap = getxattr(filepath, 'security.capability')
    except (IOError, OSError):
        return None

    version, = unpack_from('<I', bincap)
    revision = (version & 0xFF000000) >> 24

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


def getfilesec(filepath):
    filestat = lstat(filepath)

    header = ''

    if S_ISREG(filestat.st_mode):
        try:
            with open(filepath, 'rb') as fileobj:
                header = fileobj.read(4096)
        except IOError:
            pass

    owner_uid = filestat.st_uid
    try:
        owner_user = as_unicode_string(
            getpwuid(owner_uid).pw_name
        )
    except KeyError:
        owner_user = None

    owner_domain = None  # Unsupported?
    owner = (owner_uid, owner_user, owner_domain)

    group_gid = filestat.st_gid
    try:
        group_user = as_unicode_string(
            getgrgid(group_gid).gr_name
        )
    except KeyError:
        group_user = None

    group_domain = None  # Unsupported?
    group = (group_gid, group_user, group_domain)

    caps = None
    acls = None
    sectx = None
    xattrs = []

    try:
        xattrs = list_xattrs(filepath)
        caps = getcaps(filepath)
        acls = getacls(filepath)
        sectx = getselinux(filepath)

    except IOError:
        pass

    caps_text = None

    security_xattrs = [
        x for x in xattrs if x.startswith((b'security.', b'system.posix_'))
    ]

    other_xattrs = [
        x for x in xattrs if not x.startswith((b'security.', b'system.posix_'))
    ]

    other_xattr_values = []
    for xattr in other_xattrs:
        try:
            other_xattr_values.append('{}: {}'.format(
                try_as_unicode_string(xattr, fail=False),
                try_as_unicode_string(
                    getxattr(filepath, xattr), fail=False)
            ))
        except IOError:
            pass

    if caps:
        permitted_flags, inheritable_flags, effective = caps

        caps_text = ''
        flags = ''

        if effective:
            flags += 'e'

        if permitted_flags == inheritable_flags or (
                permitted_flags and not inheritable_flags):
            caps_text = ','.join(permitted_flags)
            if inheritable_flags:
                flags += 'i'
            flags += 'p'

        elif not permitted_flags and inheritable_flags:
            caps_text = ','.join(inheritable_flags)
            flags += 'i'

        if flags:
            caps_text += '+' + flags

    link = None
    if S_ISLNK(filestat.st_mode):
        link = readlink(filepath)

    mode = mode_to_letter(filestat.st_mode) + \
        special_to_letter(filestat.st_mode)

    extra = {
        'ACLs': acls.split('\n') if acls else None,
        'CAPs': caps_text,
        'SELinux': sectx,
        'Security': security_xattrs,
        'XAttr': other_xattr_values,
        'Link': link
    }

    return int(filestat.st_ctime), int(filestat.st_atime), \
        int(filestat.st_mtime), filestat.st_size, owner, \
        group, header, mode, as_unicode_string_deep({
            k: v for k, v in extra.items() if v
        })
