# -*- encoding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from pupy.pupylib.PupyModule import PupyArgumentParser
from pupy.pupylib.PupyOutput import Success

import os

from io import open

usage  = 'Restart pupysh'
parser = PupyArgumentParser(prog='restart', description=usage)


def do(server, handler, config, args):
    argv0 = os.readlink('/proc/self/exe')
    argv = [
        x for x in open('/proc/self/cmdline').read().split('\x00') if x
    ]

    if handler.dnscnc:
        handler.display_srvinfo(Success('Stopping DNSCNC'))
        handler.dnscnc.stop()

    server.stop()
    handler.display_srvinfo(Success('Restarting'))
    os.execv(argv0, argv)
