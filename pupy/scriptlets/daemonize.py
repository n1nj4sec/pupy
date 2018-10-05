# -*- coding: utf-8 -*-

''' Daemonize the process at startup (posix only) '''

__compatibility__ = ('linux', 'posix', 'unix')

from pupy import infos
from os import fork, _exit, umask, name, setsid, dup2

def main():
    if name == 'posix':
        infos['daemonize'] = True
        if fork():   # launch child and...
            _exit(0) # kill off parent
        setsid()
        if fork():   # launch child and...
            _exit(0) # kill off parent again.
        umask(022)   # Don't allow others to write
        null = open('/dev/null', 'w+')
        for i in range(3):
            try:
                dup2(null.fileno(), i)
            except OSError:
                pass

        null.close()
