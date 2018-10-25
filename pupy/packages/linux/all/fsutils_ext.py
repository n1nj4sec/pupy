# -*- encoding: utf-8 -*-
from os import path, lstat, readlink
from stat import S_ISREG, S_ISLNK
from struct import unpack_from, unpack

from prctl import ALL_CAPS, ALL_CAP_NAMES
from posix1e import ACL, has_extended
from xattr import getxattr
from xattr import list as list_xattrs

from pwd import getpwuid
from grp import getgrgid

from pupyutils.basic_cmds import mode_to_letter, special_to_letter

def getselinux(filepath):
    try:
        sectx = getxattr(filepath, 'security.selinux')
    except (IOError, OSError):
        return None

    return sectx

def getacls(filepath):
    acls = ''

    try:
        if not has_extended(filepath):
            return None

        # posix1e doesn't work with unicode properly
        if type(filepath) == unicode:
            filepath = filepath.encode('utf-8')

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
    if not (revision == 1 and len(caps) == 8 or \
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
            with open(filepath) as fileobj:
                header = fileobj.read(4096)
        except IOError:
            pass

    owner_uid = filestat.st_uid
    try:
        owner_user = getpwuid(owner_uid).pw_name
    except KeyError:
        owner_user = None

    owner_domain = None # Unsupported?
    owner = (owner_uid, owner_user, owner_domain)

    group_gid = filestat.st_gid
    try:
        group_user = getgrgid(group_gid).gr_name
    except KeyError:
        group_user = None

    group_domain = None # Unsupported?
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
        x for x in xattrs if x.startswith(('security.', 'system.posix_'))
    ]

    other_xattrs = [
        x for x in xattrs if not x.startswith(('security.', 'system.posix_'))
    ]

    other_xattr_values = []
    for xattr in other_xattrs:
        try:
            other_xattr_values.append('{}: {}'.format(xattr, getxattr(filepath, xattr)))
        except IOError:
            pass

    if caps:
        permitted_flags, inheritable_flags, effective = caps

        caps_text = ''
        flags = ''

        if effective:
            flags += 'e'

        if permitted_flags == inheritable_flags or \
          (permitted_flags and not inheritable_flags):
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
      group, header, mode, {k:v for k,v in extra.iteritems() if v}
