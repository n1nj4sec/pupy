#!/usr/bin/env python
# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
import datetime
from pupylib.utils.decorators import threaded
import logging

# triggers and get executed at each client connection
@threaded
def on_connect(client):
    for action, command in client.pupsrv.config.items("on_connect"):
        if action=="run_module":
            args=command.split()
            module_name=args.pop(0)
            job=client.run_module(module_name, args)
            job.wait()
            client.pupsrv.handler.display_srvinfo("on_connect: %s %s"%(module_name, ' '.join(args)))
        else:
            logging.warning("unknown action %s in pupy.conf [on_connect]"%action)



