import wmi

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

DRIVE_TYPES = """
0 	unknown
1 	no_root
2 	removable
3 	fixed
4 	remote
5 	cdrom
6 	ramdisk
"""

def list_drives():
    output = []
    drive_types = dict(
        (int (i), j) for (i, j) in (l.split ("\t") for l in DRIVE_TYPES.splitlines () if l)
    )

    c = wmi.WMI()
    wql = 'SELECT Name,DriveType,Size,FreeSpace,ProviderName FROM Win32_LogicalDisk'
    output = [
        '\n%s%s%s%s%s' % (
            'Name'.ljust(10),
            'Type'.ljust(15),
            'Size (Total)'.ljust(20),
            'Size (Free)'.ljust(20),
            'Mapped to'.ljust(10)
        ),
        '%s%s%s%s%s' % (
            '----'.ljust(10),
            '----'.ljust(15),
            '------------'.ljust(20),
            '-----------'.ljust(20),
            '---------'.ljust(10)
        )
    ]

    data  = []
    for disk in c.query(wql):
        unc_path = ''
        if disk.ProviderName:
            unc_path = disk.ProviderName

        name = disk.Name + '\\'
        driveType = drive_types[int(disk.DriveType)]
        size = sizeof_fmt(disk.Size)
        free = sizeof_fmt(disk.FreeSpace)

        output.append(
            '%s%s%s%s%s' % (
                name.ljust(10),
                driveType.ljust(15),
                size.ljust(20),
                free.ljust(20),
                unc_path
            )
        )

    return '\n'.join(output)+'\n'

def shared_folders():
    c = wmi.WMI()
    shared = c.query("Select * from Win32_Share Where Type=0")
    if not shared:
        return ''

    output = [
        '%s%s' % ('Name'.ljust(12), 'Path'.ljust(15)),
        '%s%s' % ('----'.ljust(12), '----'.ljust(15))
    ] + [
        '%s%s' % (s.Name.ljust(12), s.Path.ljust(15)) for s in shared
    ]

    return '\n'.join(output)+'\n'
