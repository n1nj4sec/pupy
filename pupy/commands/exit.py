# -*- encoding: utf-8 -*-

from pupylib.PupyModule import PupyArgumentParser
from pupylib.PupyOutput import Success

usage = 'Exit Shell'
parser = PupyArgumentParser(prog='exit', description=usage)

def do(server, handler, config, args):
    for job in server.jobs.itervalues():
        job.stop()

    if server.dnscnc:
        handler.display_srvinfo('Stopping DNSCNC')
        server.dnscnc.stop()

    server.stop()
