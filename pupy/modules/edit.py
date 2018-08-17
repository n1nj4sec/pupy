# -*- coding: utf-8 -*-

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.PupyCompleter import remote_path_completer
from os.path import splitext, basename
from os import environ

import hashlib
import tempfile
import subprocess
import shlex

__class_name__='Edit'
@config(cat='manage')
class Edit(PupyModule):
    ''' Edit remote file locally (download->edit->upload) '''

    dependencies = ['pupyutils.basic_cmds']

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog='edit', description=cls.__doc__)
        cls.arg_parser.add_argument(
            'remote_file', metavar='<remote_path>',
            completer=remote_path_completer)

    def run(self, args):
        fgetcontent = self.client.remote('pupyutils.basic_cmds', 'fgetcontent', False)
        fputcontent = self.client.remote('pupyutils.basic_cmds', 'fputcontent', False)

        base, ext = splitext(args.remote_file)

        with tempfile.NamedTemporaryFile(suffix=ext, prefix=basename(base)) as local:
            content = fgetcontent(args.remote_file)
            h1 = hashlib.md5(content).digest()
            local.write(content)
            local.flush()

            del content

            editor = self.config.get('default_viewers', 'editor')
            if not editor:
                editor = environ.get('EDITOR', 'vi')

            cmdline = shlex.split(editor)
            f_found = False

            for i, pos in enumerate(cmdline):
                if '%f' in pos:
                    cmdline[i] = pos.replace('%f', local.name)
                    f_found = True

            if not f_found:
                cmdline.append(local.name)

            subprocess.check_call(cmdline)

            local.seek(0)
            content = local.read()
            h2 = hashlib.md5(content).digest()

            if h1 != h2:
                fputcontent(args.remote_file, content)
