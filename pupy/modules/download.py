# -*- coding: utf-8 -*-
from pupylib.PupyModule import *
from pupylib.PupyCompleter import *
from pupylib.PupyConfig import PupyConfig
from rpyc.utils.classic import download_file
import os
import os.path
import time

__class_name__="DownloaderScript"

def try_unicode(path):
    if type(path) != unicode:
        try:
            return path.decode('utf-8')
        except UnicodeDecodeError:
            pass

    return path

def download(conn, remotepath, localpath, filter=None, ignore_invalid=False, chunk_size=16000, log=None):
    remotepath = try_unicode(remotepath)
    localpath = try_unicode(localpath)

    if conn.modules.os.path.isdir(remotepath):
        download_dir(conn, remotepath, localpath, filter, chunk_size, log)
    elif conn.modules.os.path.isfile(remotepath):
        if log:
            start_time = time.time()

        download_file(conn, remotepath, localpath, chunk_size)

        if log:
            size = os.path.getsize(localpath)
            total_time = round(time.time()-start_time, 2)
            kb_size = round(size / 10**3, 2)
            log('{} -> {}: {}KB ({}KB/s)'.format(
                remotepath, localpath,
                kb_size,
                round((size/total_time)/10**3, 2)))
    else:
        if not ignore_invalid:
            raise ValueError("cannot download %r" % (remotepath,))

def download_dir(conn, remotepath, localpath, filter=None, chunk_size=16000, log=None):
    if not os.path.isdir(localpath):
        os.makedirs(localpath)
    for fn in conn.modules.os.listdir(remotepath):
        if not filter or filter(fn):
            rfn = conn.modules.os.path.join(remotepath, fn)
            lfn = os.path.join(localpath, fn)
            download(conn, rfn, lfn, filter=filter, ignore_invalid=True, chunk_size=chunk_size, log=log)

@config(category="manage")
class DownloaderScript(PupyModule):
    """ download a file/directory from a remote system """
    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog='download', description=self.__doc__)
        self.arg_parser.add_argument('-v', '--verbose', action='store_true', default=False,
                                         help='Be verbose during download')
        self.arg_parser.add_argument('remote_file', metavar='<remote_path>')
        self.arg_parser.add_argument('local_file', nargs='?', metavar='<local_path>', completer=path_completer)

    def run(self, args):
        ros = self.client.conn.modules['os']
        remote_file = ros.path.expandvars(args.remote_file)

        if args.local_file:
            local_file = os.path.expandvars(args.local_file)

            if os.path.isdir(local_file):
                local_file = os.path.join(local_file, ros.path.basename(remote_file))
        else:
            config = PupyConfig()
            filesdir = config.get_folder('downloads', {'%c': self.client.short_name()})
            remote_file_basename = ros.path.basename(remote_file)
            local_file = os.path.join(filesdir, remote_file_basename)

        local_dir = os.path.dirname(local_file)
        if not os.path.exists(local_dir):
            os.makedirs(local_dir)

        self.info('downloading %s ...'%remote_file)

        try:
            download(
                self.client.conn,
                remote_file, local_file,
                chunk_size=8*1024*1024, log=self.info if args.verbose else None
            )
            self.success('downloaded from remote:%s to local:%s'%(remote_file, local_file))
        except Exception, e:
            self.error(' '.join(x for x in e.args if type(x) in (str, unicode)))
