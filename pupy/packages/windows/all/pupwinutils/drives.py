# -*- encoding: utf-8 -*-

import wql

def sizeof_fmt(num, suffix='B'):
    try:
        num = int(num)
        for unit in ['','Ki','Mi','Gi','Ti','Pi','Ei','Zi']:
            if abs(num) < 1024.0:
                return "%3.1f %s%s" % (num, unit, suffix)
            num /= 1024.0
        return "%.1f %s%s" % (num, 'Yi', suffix)
    except:
        return '0.00 B'

# Drive types explaination
# 0 => The drive type cannot be determined.
# 1 => The root path is invalid; for example, there is no volume mounted at the specified path.
# 2 => The drive has removable media; for example, a floppy drive, thumb drive, or flash card reader.
# 3 => The drive has fixed media; for example, a hard disk drive or flash drive.
# 4 => The drive is a remote (network) drive.
# 5 => The drive is a CD-ROM drive.
# 6 => The drive is a RAM disk.

DRIVE_TYPES = (
    'unknown',
    'no_root',
    'removable',
    'fixed',
    'remote',
    'cdrom',
    'ramdisk'
)

WQL_DRIVES_QUERY = 'SELECT Name,DriveType,Size,FreeSpace,ProviderName FROM Win32_LogicalDisk'
WQL_SHARES_QUERY = 'SELECT * FROM Win32_Share Where Type=0'

def list_drives():
    output = []

    for disk in wql.execute(WQL_DRIVES_QUERY):
        unc_path = ''
        if disk.ProviderName:
            unc_path = disk.ProviderName

        name = disk.Name + '\\'
        driveType = DRIVE_TYPES[int(disk.DriveType)]
        size = sizeof_fmt(disk.Size)
        free = sizeof_fmt(disk.FreeSpace)

        output.append((
            name, driveType, size, free, unc_path
        ))

    return tuple(output)

def shared_folders():
    shared = wql.execute(WQL_SHARES_QUERY)
    if not shared:
        return ''

    return tuple(
        (item.Name, item.Path) for item in shared
    )
