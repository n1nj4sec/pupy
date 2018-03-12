#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import marshal
import struct
import base64
import os.path
import os
import argparse

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(os.path.join(ROOT, 'pupy', 'pupylib'))

from PupyCompile import pupycompile

remove_stdout='''
import sys
sys.tracebacklimit = 0
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

    # We are interested to consume embedded modules
    # This will help to preload some
    preload = ''
    if args.debug:
        with open(os.path.join('..','additional_imports.py')) as f:
            preload = f.read()

    pupyimporter = pupycompile(pupyimporter, raw=True, debug=args.debug)

    if not args.debug:
        print 'Generate bootloader with blackholed stderr/stdout'

    bootloader = [
        remove_stdout if not args.debug else 'print "DEBUG"\n',
        'import sys; sys.path=[]; sys.path_hooks=[]; sys.meta_path=[];' + (
            'sys.argv = [];' if not args.pass_argv else ''
        ) + 'sys.prefix = "";\n',
        pupyload.format('pupyimporter', repr(pupyimporter)),
        'import pupyimporter\n'
        'pupyimporter.install({})\n'.format(args.debug),
        preload+'\n',
        pp+'\n',
    ]

    if not os.path.exists('resources'):
        os.makedirs('resources')

    with open(os.path.join('resources', 'bootloader.pyc'),'wb') as w:
        w.write(pupycompile('\n'.join(bootloader), raw=True, debug=args.debug, main=True))
