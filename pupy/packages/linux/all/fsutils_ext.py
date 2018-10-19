# -*- encoding: utf-8 -*-
from os import path
from struct import unpack_from, unpack

from prctl import ALL_CAPS, ALL_CAP_NAMES
from posix1e import ACL
from xattr import getxattr

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
