# -*- encoding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from pupylib.PupyModule import PupyArgumentParser

usage = 'Exit Shell'
parser = PupyArgumentParser(prog='exit', description=usage)

def do(server, handler, config, args):
    for job in server.jobs.values():
        job.stop()

    if server.dnscnc:
        handler.display_srvinfo('Stopping DNSCNC')
        server.dnscnc.stop()

    server.stop()
