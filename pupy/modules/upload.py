# -*- coding: utf-8 -*-
from pupylib.PupyModule import *
from pupylib.PupyCompleter import *
from rpyc.utils.classic import upload
import os
import os.path

__class_name__="UploaderScript"

@config(cat="manage")
class UploaderScript(PupyModule):
    """ upload a file/directory to a remote system """
    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog='upload', description=self.__doc__)
        self.arg_parser.add_argument('local_file', metavar='<local_path>', completer=path_completer)
        self.arg_parser.add_argument('remote_file', metavar='<remote_path>')
    def run(self, args):
        dst = self.client.conn.modules['os.path'].expandvars(args.remote_file)
        if dst.endswith('.'):
            dst = dst.replace('.', args.local_file.split(os.sep)[-1])
        upload(self.client.conn, args.local_file, dst)
        self.success("file local:%s uploaded to remote:%s"%(args.local_file, dst))
