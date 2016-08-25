# -*- coding: utf-8 -*-

import subprocess

from pupylib.PupyModule import *

import subprocess
import time
import datetime

__class_name__="PExec"

@config(cat="admin")
class PExec(PupyModule):
    """ Execute shell commands non-interactively on a remote system in background using popen"""

    pool_time = 1
    pipe = None
    completed = False
    terminate = False
    # daemon = True

    dependencies = [ "pupyutils.safepopen" ]

    def init_argparse(self):
        self.arg_parser = PupyArgumentParser(prog='pexec', description=self.__doc__)
        self.arg_parser.add_argument(
            '-log',
            help='Save output to file',
        )
        self.arg_parser.add_argument(
            '-n',
            action='store_true',
            help='Don\'t catch stderr',
        )
        self.arg_parser.add_argument(
            '-F',
            action='store_true',
            help='Don\'t hide application window (Windows only)'
        )
        self.arg_parser.add_argument(
            '-s',
            action='store_true',
            help='Start in shell',
        )
        self.arg_parser.add_argument(
            'arguments',
            nargs=argparse.REMAINDER,
            help='CMD args'
        )

    def run(self, args):
        if not args.arguments:
            self.error('No command specified {}'.format(args.__dict__))
            return

        rsubprocess = self.client.conn.modules['subprocess']
        cmdargs = args.arguments

        if args.s:
            cmdargs = [
                'cmd.exe', '/c',
            ] + cmdargs if self.client.is_windows() else [
                '/bin/sh', '-c', ' '.join(
                    '"'+x.replace('"','\"')+'"' for x in cmdargs
                )
            ]

        cmdenv = {
            'stdin': subprocess.PIPE,
            'stderr': (None if args.n else subprocess.STDOUT),
            'stdout': subprocess.PIPE,
            'universal_newlines': False,
            'bufsize': 1,
        }

        if self.client.is_windows():
            if not args.F:
                startupinfo = rsubprocess.STARTUPINFO()
                startupinfo.dwFlags |= rsubprocess.STARTF_USESHOWWINDOW
                cmdenv.update({
                    'startupinfo': startupinfo,
                })
        else:
            cmdenv.update({
                'close_fds': True,
            })

        popen = self.client.conn.modules['pupyutils.safepopen'].SafePopen
        self.pipe = popen(cmdargs, **cmdenv)

        rdatetime = self.client.conn.modules['datetime']

        self.success('Started at (local:{} / remote:{}): '.format(
            datetime.datetime.now(), rdatetime.datetime.now()))
        self.success('Command: {}'.format(' '.join(
            x if not ' ' in x else "'" + x + "'" for x in cmdargs
        )))

        log = None
        if args.log:
            log = open(args.log, 'w')

        for data in self.pipe.execute():
            if data:
                if not self.terminate:
                    self.log(data)
                if log:
                    log.write(data)

        if log:
            log.close()

        if self.pipe.returncode == 0:
            self.success('Finished at (local:{} / remote:{}): '.format(
                datetime.datetime.now(), rdatetime.datetime.now()))
        else:
            self.error('Finished at (local:{} / remote:{})'.format(
                datetime.datetime.now(), rdatetime.datetime.now(),
                ))
            self.error('Ret: {}'.format(self.pipe.returncode))

        if hasattr(self.job, 'id'):
            self.job.pupsrv.handler.display_srvinfo('(Job id: {}) Command {} completed'.format(
                self.job.id, cmdargs))

    def interrupt(self):
        if not self.completed and self.pipe:
            self.error('Stopping command')
            self.pipe.terminate()
            self.terminate = True
            self.error('Stopped')
