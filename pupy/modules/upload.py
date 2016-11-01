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
        self.arg_parser.add_argument('remote_file', nargs='?', metavar='<remote_path>')

    def run(self, args):
        ros = self.client.conn.modules['os']
        localfile =  os.path.expandvars(args.local_file)

        if args.remote_file:
            remotefile = ros.path.expandvars(args.remote_file)
        else:
            ros = self.client.conn.modules['os']
            rtempfile = self.client.conn.modules['tempfile']
            tempdir = rtempfile.gettempdir()
            remotefile = ros.path.join(tempdir, os.path.basename(localfile))

        if remotefile.endswith('.'):
            remotefile = os.path.join(os.path.dirname(remotefile), args.local_file.split(os.sep)[-1])

        if os.path.isfile(localfile) and ros.path.isdir(remotefile):
            remotefile = ros.path.join(remotefile, os.path.basename(localfile))

        self.info(
            "Uploading local:%s to remote:%s (size=%d)"%(
                localfile,
                remotefile,
                os.stat(localfile).st_size
            )
        )

        upload(
            self.client.conn,
            localfile,
            remotefile
        )

        self.success("file local:%s uploaded to remote:%s"%(localfile, remotefile))

        self.client.conn.modules['os'].chmod(
            remotefile,
            os.stat(localfile).st_mode
        )
