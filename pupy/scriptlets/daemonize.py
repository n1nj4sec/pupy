# -*- coding: utf-8 -*-

''' daemonize the process at startup (posix only) '''

import pupy, os

def main():
    if os.name == 'posix':
        pupy.infos['daemonize']=True
        if os.fork():   # launch child and...
            os._exit(0) # kill off parent
        os.setsid()
        if os.fork():   # launch child and...
            os._exit(0) # kill off parent again.
        os.umask(022)   # Don't allow others to write
        null=os.open('/dev/null', os.O_RDWR)
        for i in range(3):
            try:
                os.dup2(null, i)
            except OSError, e:
                if e.errno != errno.EBADF:
                    raise
        os.close(null)
