# -*- coding: utf-8 -*-

import os

class MountInfo(object):
    def __init__(self, line):
        src, dst, fsname, options, _, _ = (
            option.replace(r'\040', ' ') for option in line.split(' ')
        )

        self.src = src
        self.dst = dst
        self.fsname = fsname
        self._options = [ option.split('=') for option in options.split(',') ]

        try:
            vfsstat = os.statvfs(self.dst)
            self.free = vfsstat.f_bfree*vfsstat.f_bsize
            self.total = vfsstat.f_blocks*vfsstat.f_bsize
            self.files = vfsstat.f_files
            self.exception = None

            Kb = 1024
            Mb = 1024*Kb
            Gb = 1024*Mb
            Tb = 1024*Gb

            if self.total > 0:
                if self.free > Tb:
                    self.hfree = '{}Tb'.format(self.free / Tb)
                elif self.free > Gb:
                    self.hfree = '{}Gb'.format(self.free / Gb)
                elif self.free > Mb:
                    self.hfree = '{}Mb'.format(self.free / Mb)
                elif self.free > Kb:
                    self.hfree = '{}Kb'.format(self.free / Kb)
                else:
                    self.hfree = '{}b'.format(self.free)

                self.pused = 100 - int(self.free/float(self.total)*100)

        except Exception as e:
            self.exception = e.message
            self.total = None
            self.free = None
            self.files = None
            self.hfree = None
            self.pfree = None

        if self.fsname == 'tmpfs':
            self.fstype = 'tmpfs'
        elif self.fsname in ('smb', 'cifs', 'nfs', 'nfsv3', 'nfs4'):
            self.fstype = 'network'
        elif self.fsname.startswith('cgroup'):
            self.fstype = 'cgroup'
        elif self.src.startswith('/dev/mapper'):
            self.fstype = 'dm'
        elif fsname.startswith('fuse'):
            self.fstype = 'fuse'
        elif self.src == 'systemd-1' and self.fsname == 'autofs':
            self.fstype = 'automount'
        elif self.src == 'sunrpc':
            self.fstype = 'rpc'
        elif src == fsname or fsname in (
                'devtmpfs', 'sysfs', 'proc', 'devpts', 'securityfs',
                'pstore', 'mqueue', 'hugetlbfs', 'debugfs', 'binfmt_misc'
            ):
            self.fstype = 'kernel'
        else:
            self.fstype = 'block'

    @property
    def options(self):
        return [
            option for option in self._options if not any([
                option[0].startswith(value) for value in (
                    'relatime', 'fd', 'pgrp', 'timeout', 'minproto',
                    'maxproto', 'direct', 'pipe_ino', 'iocharset',
                    'codepage', 'lazytime', 'background_gc', 'inline_data',
                    'discard', 'flush_merge', 'extent_cache', 'mode',
                    'active_logs', 'commit', 'data', 'nr_inodes', 'size',
                    'shortnames', 'utf8', 'errors', 'cache', 'rsize',
                    'wsize', 'echo_interval', 'actime', 'blksize',
                    'serverino', 'posixpaths', 'mapposix'
                )
            ])
        ]

    def __repr__(self):
		return ' '.join([
            '"{}"'.format(getattr(self, x)) for x in [
                'src', 'dst', 'fsname', 'free'
            ] + ','.join([ '='.join(kv) for kv in self._options ])
        ])

def mounts():
    mountinfo = {}
    with open('/proc/self/mounts', 'r') as mounts:
        for line in mounts:
            info = MountInfo(line)
            if not info.fstype in mountinfo:
                mountinfo[info.fstype] = [ info ]
            else:
                mountinfo[info.fstype].append(info)
    return mountinfo
