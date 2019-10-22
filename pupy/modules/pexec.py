# -*- coding: utf-8 -*-

from pupylib.PupyModule import (
    config, PupyModule, PupyArgumentParser,
    REQUIRE_STREAM
)

import datetime
import subprocess
import threading
import chardet

from argparse import REMAINDER

__class_name__="PExec"


@config(cat="admin")
class PExec(PupyModule):
    """ Execute shell commands non-interactively on a remote system in background using popen"""

    terminate_pipe = None
    terminated = False
    encoding = None
    errors = None

    dependencies = ["pupyutils.safepopen"]
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
        encodings = cls.arg_parser.add_mutually_exclusive_group()
        encodings.add_argument(
            '-E',
            action='store_true',
            help='Disable auto decoding',
        )
        encodings.add_argument(
            '-e', help='Use encoding to decode stream',
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
            nargs=REMAINDER,
            help='CMD args'
        )

    def run(self, args):
        if not args.arguments:
            self.error('No command specified {}'.format(args.__dict__))
            return

        if args.E or not self.client.is_windows():
            self.encoding = False
        elif args.e:
            self.encoding = args.e

        cmdargs = args.arguments
        safe_exec = self.client.remote('pupyutils.safepopen', 'safe_exec', False)
        cmdenv = {
            'stderr': (None if args.n else subprocess.STDOUT),
            'universal_newlines': False,
            'detached': args.N
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
                        '"'+x.replace('"', '\"')+'"' for x in cmdargs
                    )
                ]

        if args.set_uid:
            cmdenv['suid'] = args.set_uid

        close_event = threading.Event()

        def on_read(data):
            if self.encoding is None:
                try:
                    if not self.encoding:
                        encoding = chardet.detect(data)
                        if encoding['confidence'] > 0.7 and \
                          encoding['encoding'] != 'ascii':
                            self.encoding = encoding['encoding']
                except Exception, e:
                    self.errors = e

            if self.encoding:
                try:
                    data = data.decode(
                        self.encoding
                    ).encode('utf-8')
                except UnicodeError, e:
                    self.errors = e


            self.stdout.write(data)

        if type(cmdargs) == list:
            cmdargs = tuple(cmdargs)

        kwargs = tuple((k,v) for k,v in cmdenv.iteritems())

        self.terminate_pipe, get_returncode = safe_exec(
            on_read, close_event.set, cmdargs, kwargs
        )

        if hasattr(self.job, 'id'):
            self.success('Started at {}'.format(
                datetime.datetime.now()))

        close_event.wait()

        retcode = get_returncode()
        if retcode == 0:
            self.success('Completed at {}'.format(datetime.datetime.now()))
        elif retcode is not None:
            self.error(
                'Ret: {} at {}'.format(retcode, datetime.datetime.now()))

    def interrupt(self):
        if not self.terminated and self.terminate_pipe:
            self.terminated = True
            self.error('Stopping command')
            self.terminate_pipe()
            self.error('Stopped')
