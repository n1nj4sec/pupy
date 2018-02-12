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
        rexpandvars = self.client.remote('os.path', 'expandvars', False)
        rbasename = self.client.remote('os.path', 'basename', False)

        remote_file = rexpandvars(args.remote_file)

        if args.local_file:
            local_file = os.path.expandvars(args.local_file)

            if os.path.isdir(local_file):
                local_file = os.path.join(local_file, rbasename(remote_file))
        else:
            config = PupyConfig()
            filesdir = config.get_folder('downloads', {'%c': self.client.short_name()})
            remote_file_basename = rbasename(remote_file)
            local_file = os.path.join(filesdir, remote_file_basename)

        local_dir = os.path.dirname(local_file)
        if not os.path.exists(local_dir):
            os.makedirs(local_dir)

        self.info('downloading %s ...'%remote_file)

        try:
            self.download(remote_file, local_file, chunk_size=8*1024*1024,
                          log=self.info if args.verbose else None)
            self.success('downloaded from remote:%s to local:%s'%(remote_file, local_file))
        except Exception, e:
            self.error(' '.join(x for x in e.args if type(x) in (str, unicode)))

    def download(self, remotepath, localpath, filter=None, ignore_invalid=False, chunk_size=16000, log=None):
        remotepath = try_unicode(remotepath)
        localpath = try_unicode(localpath)

        risdir = self.client.remote('os.path', 'isdir', False)
        risfile = self.client.remote('os.path', 'isfile', False)

        if risdir(remotepath):
            self.download_dir(remotepath, localpath, filter, chunk_size)

        elif risfile(remotepath):
            if log:
                start_time = time.time()

            download_file(self.client.conn, remotepath, localpath, chunk_size)

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

    def download_dir(self, remotepath, localpath, filter=None, chunk_size=16000, log=None):
        risdir = self.client.remote('os.path', 'isdir', False)
        rlistdir = self.client.remote('os.path', 'listdir')
        rjoin = self.client.remote('os.path', 'join')

        if not risdir(localpath):
            os.makedirs(localpath)

        for fn in rlistdir(remotepath):
            if not filter or filter(fn):
                rfn = rjoin(remotepath, fn)
                lfn = os.path.join(localpath, fn)
                self.download(
                    rfn, lfn, filter=filter,
                    ignore_invalid=True, chunk_size=chunk_size)
