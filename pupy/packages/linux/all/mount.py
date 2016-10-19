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
        self._options = options.split(',')

        try:
            vfsstat = os.statvfs(self.dst)
            self.free = vfsstat.f_bfree*vfsstat.f_bsize
            self.total = vfsstat.f_blocks*vfsstat.f_bsize
            self.files = vfsstat.f_files
            self.exception = None
        except Exception as e:
            self.exception = e.message
            self.total = None
            self.free = None
            self.files = None

        if self.fsname == 'tmpfs':
            self.fstype = 'tmpfs'
        elif self.fsname.startswith('cgroup'):
            self.fstype = 'cgroup'
        elif self.src.startswith('/dev/mapper'):
            self.fstype = 'dm'
        elif fsname.startswith('fuse.'):
            self.fstype = 'fuse'
        elif self.src == 'systemd-1' and self.fsname == 'autofs':
            self.fstype = 'automount'
        elif self.src == 'sunrpc':
            self.fstype = 'rpc'
        elif src == fsname:
            self.fstype = 'kernel'
        else:
            self.fstype = 'block'

    @property
    def options(self):
        return [
            option for option in self._options if not any([
                option.startswith(value) for value in (
                    'relatime', 'fd', 'pgrp', 'timeout',
                    'minproto', 'maxproto', 'direct', 'pipe_ino',
                    'iocharset', 'codepage', 'lazytime', 'background_gc',
                    'inline_data', 'discard', 'flush_merge', 'extent_cache',
                    'mode', 'active_logs', 'commit', 'data', 'nr_inodes', 'size',
                    'shortnames', 'utf8', 'errors'
                )
            ])
        ]

    def __repr__(self):
        if self.fsname in ( 'tmpfs', 'cgroup', 'fuse', 'automount', 'rpc', 'kernel' ):
            return '{} type={} options={}'.format(
                self.dst, self.fstype, ','.join(self.options)
            )
        else:
            Kb = 1024
            Mb = 1024*Kb
            Gb = 1024*Mb
            Tb = 1024*Gb

            if self.total > 0:
                if self.free > Tb:
                    free = '{}Tb'.format(self.free / Tb)
                elif self.free > Gb:
                    free = '{}Gb'.format(self.free / Gb)
                elif self.free > Mb:
                    free = '{}Mb'.format(self.free / Mb)
                elif self.free > Kb:
                    free = '{}Kb'.format(self.free / Kb)
                else:
                    free = '{}b'.format(self.free)

                free = ' free={}%({})'.format(int(self.free/float(self.total)*100), free)
            elif self.exception:
                free = ' free=(error: {})'.format(self.exception)
            else:
                free = ' '

            return '{} src={} fs={} options={}{}'.format(
                self.dst, self.src, self.fsname, ','.join(self.options), free
            )

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
