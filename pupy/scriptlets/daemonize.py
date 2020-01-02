# -*- coding: utf-8 -*-

''' Daemonize the process at startup (posix only) '''
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

__compatibility__ = ('linux', 'posix', 'unix')

from io import open
from os import fork, _exit, umask, name, setsid, dup2
from pupy import infos


def main():
    if name == 'posix':
        infos['daemonize'] = True
        if fork():   # launch child and...
            _exit(0) # kill off parent
        setsid()
        if fork():   # launch child and...
            _exit(0) # kill off parent again.
        umask(0o22)   # Don't allow others to write
        null = open('/dev/null', 'w+b')
        for i in range(3):
            try:
                dup2(null.fileno(), i)
            except OSError:
                pass

        null.close()
