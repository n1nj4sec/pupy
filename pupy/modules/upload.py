# -*- coding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.PupyCompleter import path_completer, remote_dirs_completer

from rpyc.utils.classic import upload

import os
import os.path

__class_name__="UploaderScript"

@config(cat="manage")
class UploaderScript(PupyModule):
    """ upload a file/directory to a remote system """

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog='upload', description=cls.__doc__)
        cls.arg_parser.add_argument('local_file', metavar='<local_path>', completer=path_completer)
        cls.arg_parser.add_argument('remote_file', nargs='?', metavar='<remote_path>',
                                    completer=remote_dirs_completer)

    def run(self, args):
        localfile = os.path.expandvars(args.local_file)

        rexpandvars = self.client.remote('os.path', 'expandvars')
        rjoin = self.client.remote('os.path', 'join')
        risdir = self.client.remote('os.path', 'isdir', False)

        if args.remote_file:
            remotefile = rexpandvars(args.remote_file)
        else:
            rtempfile = self.client.conn.modules['tempfile']
            tempdir = rtempfile.gettempdir()
            remotefile = rjoin(tempdir, os.path.basename(localfile))

        if remotefile.endswith('.'):
            remotefile = os.path.join(os.path.dirname(remotefile), args.local_file.split(os.sep)[-1])

        if os.path.isfile(localfile) and risdir(remotefile):
            remotefile = rjoin(remotefile, os.path.basename(localfile))

        size = os.stat(localfile).st_size

        self.info(
            "Uploading local:%s to remote:%s (size=%d)"%(
                localfile,
                remotefile,
                size
            )
        )

        try:
            upload(self.client.conn, localfile, remotefile, chunk_size=8*1024*1024)
        except Exception, e:
            self.error(' '.join(x for x in e.args if type(x) in (str, unicode)))
            return

        self.success("file local:%s uploaded to remote:%s"%(localfile, remotefile))

        self.client.conn.modules['os'].chmod(
            remotefile,
            os.stat(localfile).st_mode
        )
